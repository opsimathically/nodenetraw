use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{
    CancellationToken, MAX_PENDING_ROUTE_QUERIES, MAX_ROUTE_QUERY_DEADLINE, RefreshOutcome,
    RouteContext, RoutePlan, RouteQuery, SnapshotError, SnapshotResource,
};

enum DriverCommand {
    Resolve {
        query: RouteQuery,
        deadline: Instant,
        cancellation: CancellationToken,
        response: SyncSender<Result<RoutePlan, SnapshotError>>,
    },
    Refresh {
        deadline: Instant,
        cancellation: CancellationToken,
        response: SyncSender<Result<RefreshOutcome, SnapshotError>>,
    },
}

/// One bounded background owner for serialized refresh and route-query work.
///
/// The driver owns exactly one [`RouteContext`] and one worker thread. It is an
/// internal building block for the future scanner runtime, not a thread-per-query
/// abstraction. Every admitted operation has an enqueue-time deadline and a
/// cooperative cancellation token.
pub struct RouteContextDriver {
    commands: SyncSender<DriverCommand>,
    pending: Arc<AtomicUsize>,
    active: Arc<Mutex<Option<CancellationToken>>>,
    shutdown: CancellationToken,
    worker: Option<JoinHandle<()>>,
}

impl RouteContextDriver {
    /// Opens a context in the calling thread's namespace and transfers it to one
    /// bounded serialized worker.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError`] when the read-only context or worker cannot be
    /// created.
    pub fn new() -> Result<Self, SnapshotError> {
        let context = RouteContext::new()?;
        let (commands, receiver) = mpsc::sync_channel(MAX_PENDING_ROUTE_QUERIES);
        let pending = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(Mutex::new(None));
        let shutdown = CancellationToken::new();
        let worker_pending = Arc::clone(&pending);
        let worker_active = Arc::clone(&active);
        let worker_shutdown = shutdown.clone();
        let worker = thread::Builder::new()
            .name("nodenet-route-context".into())
            .spawn(move || {
                run_driver(
                    context,
                    &receiver,
                    &worker_pending,
                    &worker_active,
                    &worker_shutdown,
                );
            })
            .map_err(|error| SnapshotError::io("spawn route-context driver", error))?;
        Ok(Self {
            commands,
            pending,
            active,
            shutdown,
            worker: Some(worker),
        })
    }

    /// Admits one route lookup without blocking the caller on netlink I/O.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError`] if the deadline is invalid, the bounded owner
    /// queue is full, or the driver has stopped.
    pub fn resolve_route(
        &self,
        query: RouteQuery,
    ) -> Result<PendingContextOperation<RoutePlan>, SnapshotError> {
        validate_deadline(query.deadline)?;
        let deadline = Instant::now()
            .checked_add(query.deadline)
            .ok_or(SnapshotError::DeadlineExceeded)?;
        let cancellation = CancellationToken::new();
        let (response, receiver) = mpsc::sync_channel(1);
        self.admit(DriverCommand::Resolve {
            query,
            deadline,
            cancellation: cancellation.clone(),
            response,
        })?;
        Ok(PendingContextOperation::new(
            receiver,
            cancellation,
            deadline,
        ))
    }

    /// Admits one nonblocking notification drain/resync operation.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError`] if the deadline is invalid, the bounded owner
    /// queue is full, or the driver has stopped.
    pub fn refresh(
        &self,
        deadline: Duration,
    ) -> Result<PendingContextOperation<RefreshOutcome>, SnapshotError> {
        validate_deadline(deadline)?;
        let deadline = Instant::now()
            .checked_add(deadline)
            .ok_or(SnapshotError::DeadlineExceeded)?;
        let cancellation = CancellationToken::new();
        let (response, receiver) = mpsc::sync_channel(1);
        self.admit(DriverCommand::Refresh {
            deadline,
            cancellation: cancellation.clone(),
            response,
        })?;
        Ok(PendingContextOperation::new(
            receiver,
            cancellation,
            deadline,
        ))
    }

    fn admit(&self, command: DriverCommand) -> Result<(), SnapshotError> {
        reserve_pending(&self.pending)?;
        match self.commands.try_send(command) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                self.pending.fetch_sub(1, Ordering::AcqRel);
                Err(pending_limit_error(MAX_PENDING_ROUTE_QUERIES + 1))
            }
            Err(TrySendError::Disconnected(_)) => {
                self.pending.fetch_sub(1, Ordering::AcqRel);
                Err(SnapshotError::ContextUnavailable)
            }
        }
    }
}

impl Drop for RouteContextDriver {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(cancellation) = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            cancellation.cancel();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Awaitable result of one bounded context-driver operation.
pub struct PendingContextOperation<T> {
    receiver: Receiver<Result<T, SnapshotError>>,
    cancellation: CancellationToken,
    deadline: Instant,
    completed: bool,
}

impl<T> PendingContextOperation<T> {
    fn new(
        receiver: Receiver<Result<T, SnapshotError>>,
        cancellation: CancellationToken,
        deadline: Instant,
    ) -> Self {
        Self {
            receiver,
            cancellation,
            deadline,
            completed: false,
        }
    }

    /// Returns a clone of the cooperative token for cancellation from any thread.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    /// Polls once without blocking.
    ///
    /// # Errors
    ///
    /// Returns the completed operation error or context-unavailable if the owner
    /// stopped without producing a result.
    pub fn try_result(&mut self) -> Result<Option<T>, SnapshotError> {
        match self.receiver.try_recv() {
            Ok(result) => {
                self.completed = true;
                result.map(Some)
            }
            Err(TryRecvError::Empty) if Instant::now() < self.deadline => Ok(None),
            Err(TryRecvError::Empty) => {
                self.completed = true;
                self.cancellation.cancel();
                Err(SnapshotError::DeadlineExceeded)
            }
            Err(TryRecvError::Disconnected) => {
                self.completed = true;
                Err(SnapshotError::ContextUnavailable)
            }
        }
    }

    /// Waits only until the operation's enqueue-time monotonic deadline.
    ///
    /// # Errors
    ///
    /// Returns the completed operation error, deadline expiry, or
    /// context-unavailable if the owner stopped without a result.
    pub fn wait(mut self) -> Result<T, SnapshotError> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(SnapshotError::DeadlineExceeded)?;
        let result = self.receiver.recv_timeout(remaining);
        self.completed = true;
        match result {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.cancellation.cancel();
                Err(SnapshotError::DeadlineExceeded)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(SnapshotError::ContextUnavailable),
        }
    }
}

impl<T> Drop for PendingContextOperation<T> {
    fn drop(&mut self) {
        if !self.completed {
            self.cancellation.cancel();
        }
    }
}

fn run_driver(
    mut context: RouteContext,
    receiver: &Receiver<DriverCommand>,
    pending: &AtomicUsize,
    active: &Mutex<Option<CancellationToken>>,
    shutdown: &CancellationToken,
) {
    while !shutdown.is_cancelled() {
        let command = match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(command) => command,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        let cancellation = command.cancellation();
        *active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cancellation.clone());
        command.execute(&mut context, shutdown);
        *active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        pending.fetch_sub(1, Ordering::AcqRel);
    }
    pending.store(0, Ordering::Release);
}

impl DriverCommand {
    fn cancellation(&self) -> &CancellationToken {
        match self {
            Self::Resolve { cancellation, .. } | Self::Refresh { cancellation, .. } => cancellation,
        }
    }

    fn execute(self, context: &mut RouteContext, shutdown: &CancellationToken) {
        match self {
            Self::Resolve {
                mut query,
                deadline,
                cancellation,
                response,
            } => {
                let result = remaining(deadline, &cancellation, shutdown).and_then(|duration| {
                    query.deadline = duration;
                    context.resolve_route(&query, Some(&cancellation))
                });
                let result = result
                    .and_then(|plan| remaining(deadline, &cancellation, shutdown).map(|_| plan));
                let _ = response.send(result);
            }
            Self::Refresh {
                deadline,
                cancellation,
                response,
            } => {
                let result = remaining(deadline, &cancellation, shutdown)
                    .and_then(|_| context.refresh())
                    .and_then(|outcome| {
                        remaining(deadline, &cancellation, shutdown).map(|_| outcome)
                    });
                let _ = response.send(result);
            }
        }
    }
}

fn remaining(
    deadline: Instant,
    cancellation: &CancellationToken,
    shutdown: &CancellationToken,
) -> Result<Duration, SnapshotError> {
    if cancellation.is_cancelled() || shutdown.is_cancelled() {
        return Err(SnapshotError::Cancelled);
    }
    deadline
        .checked_duration_since(Instant::now())
        .ok_or(SnapshotError::DeadlineExceeded)
}

fn validate_deadline(deadline: Duration) -> Result<(), SnapshotError> {
    if deadline.is_zero() || deadline > MAX_ROUTE_QUERY_DEADLINE {
        return Err(SnapshotError::InvalidQuery(format!(
            "deadline must be greater than zero and no more than {MAX_ROUTE_QUERY_DEADLINE:?}"
        )));
    }
    Ok(())
}

fn reserve_pending(pending: &AtomicUsize) -> Result<(), SnapshotError> {
    pending
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            (value < MAX_PENDING_ROUTE_QUERIES).then_some(value + 1)
        })
        .map(|_| ())
        .map_err(|actual| pending_limit_error(actual.saturating_add(1)))
}

const fn pending_limit_error(actual: usize) -> SnapshotError {
    SnapshotError::LimitExceeded {
        resource: SnapshotResource::PendingRouteQueries,
        actual,
        maximum: MAX_PENDING_ROUTE_QUERIES,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::reserve_pending;
    use crate::{MAX_PENDING_ROUTE_QUERIES, SnapshotError, SnapshotResource};

    #[test]
    fn pending_reservation_never_exceeds_owner_ceiling() {
        let pending = AtomicUsize::new(MAX_PENDING_ROUTE_QUERIES - 1);
        reserve_pending(&pending).unwrap();
        assert_eq!(pending.load(Ordering::Acquire), MAX_PENDING_ROUTE_QUERIES);
        assert!(matches!(
            reserve_pending(&pending),
            Err(SnapshotError::LimitExceeded {
                resource: SnapshotResource::PendingRouteQueries,
                actual,
                maximum: MAX_PENDING_ROUTE_QUERIES,
            }) if actual == MAX_PENDING_ROUTE_QUERIES + 1
        ));
    }
}
