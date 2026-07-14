use std::collections::{HashMap, VecDeque};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustix::buffer::spare_capacity;
use rustix::event::{EventfdFlags, epoll, eventfd};
use rustix::io::{Errno, read, write};
use rustix::time::Timespec;

use nodenet_linux_context::{NetworkSnapshot, RefreshOutcome, RouteContext};
use nodenetscanner_engine::SessionLifecycle;

use crate::error::ScannerError;
use crate::model::ValidatedPlan;
use crate::session::{NativeScanProgress, NativeScanSummary, PullResult, SessionCore, state_name};

const MAX_SCANNERS: usize = 4;
const MAX_SESSIONS: usize = 4;
const MAX_PENDING_OPERATIONS: usize = 64;
const COMMAND_QUEUE_CAPACITY: usize = 128;
const COMMAND_BUDGET: usize = 64;
const TICK_NANOSECONDS: i64 = 2_000_000;
const BATCH_COALESCE_DELAY: Duration = Duration::from_millis(2);

type Reply<T> = SyncSender<Result<T, ScannerError>>;

pub(crate) enum Command {
    RegisterScanner {
        scanner_id: u32,
        reply: Reply<()>,
    },
    Start {
        scanner_id: u32,
        plan: Box<ValidatedPlan>,
        reply: Reply<u32>,
    },
    Pause {
        session_id: u32,
        reply: Reply<()>,
    },
    Resume {
        session_id: u32,
        reply: Reply<()>,
    },
    Cancel {
        session_id: u32,
        reply: Reply<NativeScanSummary>,
    },
    Pull {
        session_id: u32,
        pull_id: u32,
        maximum: usize,
        reply: Reply<PullResult>,
    },
    CancelPull {
        session_id: u32,
        pull_id: u32,
        reply: Reply<bool>,
    },
    Progress {
        session_id: u32,
        reply: Reply<NativeScanProgress>,
    },
    Summary {
        session_id: u32,
        reply: Reply<NativeScanSummary>,
    },
    CloseSession {
        session_id: u32,
        reply: Reply<()>,
    },
    CloseScanner {
        scanner_id: u32,
        reply: Option<Reply<()>>,
    },
    Shutdown,
}

struct SessionView {
    state: AtomicU8,
    summary: Mutex<Option<NativeScanSummary>>,
}

impl SessionView {
    fn new(_scanner_id: u32) -> Self {
        Self {
            state: AtomicU8::new(encode_state(SessionLifecycle::Created)),
            summary: Mutex::new(None),
        }
    }
}

pub(crate) struct RuntimeHandle {
    sender: SyncSender<Command>,
    wake: Arc<OwnedFd>,
    accepting: Arc<AtomicBool>,
    pending_operations: AtomicUsize,
    next_scanner_id: AtomicU32,
    views: Arc<Mutex<HashMap<u32, Arc<SessionView>>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl RuntimeHandle {
    pub(crate) fn start() -> Result<Arc<Self>, ScannerError> {
        let epoll_descriptor = epoll::create(epoll::CreateFlags::CLOEXEC)
            .map_err(|error| ScannerError::system_rustix("create scanner epoll", error))?;
        let wake = Arc::new(
            eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)
                .map_err(|error| ScannerError::system_rustix("create scanner eventfd", error))?,
        );
        epoll::add(
            &epoll_descriptor,
            &*wake,
            epoll::EventData::new_u64(0),
            epoll::EventFlags::IN,
        )
        .map_err(|error| ScannerError::system_rustix("register scanner eventfd", error))?;
        let (sender, receiver) = sync_channel(COMMAND_QUEUE_CAPACITY);
        let accepting = Arc::new(AtomicBool::new(true));
        let views = Arc::new(Mutex::new(HashMap::new()));
        let worker_accepting = Arc::clone(&accepting);
        let worker_wake = Arc::clone(&wake);
        let worker_views = Arc::clone(&views);
        let thread = thread::Builder::new()
            .name("nodenetscanner-runtime".into())
            .spawn(move || {
                run_worker(
                    epoll_descriptor,
                    worker_wake,
                    receiver,
                    worker_accepting,
                    worker_views,
                );
            })
            .map_err(|error| {
                ScannerError::internal(
                    "start scanner runtime",
                    format!("failed to spawn worker: {error}"),
                )
            })?;
        Ok(Arc::new(Self {
            sender,
            wake,
            accepting,
            pending_operations: AtomicUsize::new(0),
            next_scanner_id: AtomicU32::new(1),
            views,
            thread: Mutex::new(Some(thread)),
        }))
    }

    pub(crate) fn allocate_scanner_id(&self) -> Result<u32, ScannerError> {
        let id = self.next_scanner_id.fetch_add(1, Ordering::Relaxed);
        if id == 0 {
            self.accepting.store(false, Ordering::Release);
            return Err(ScannerError::resource(
                "create scanner",
                "scanner identifier space exhausted",
            ));
        }
        Ok(id)
    }

    pub(crate) fn submit(&self, command: Command) -> Result<(), ScannerError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(ScannerError::environment_closed("submit scanner operation"));
        }
        match self.sender.try_send(command) {
            Ok(()) => {
                wake_eventfd(&self.wake);
                Ok(())
            }
            Err(TrySendError::Full(_)) => Err(ScannerError::resource(
                "submit scanner operation",
                "scanner command queue is full",
            )),
            Err(TrySendError::Disconnected(_)) => {
                Err(ScannerError::environment_closed("submit scanner operation"))
            }
        }
    }

    pub(crate) fn request<T>(
        &self,
        make: impl FnOnce(Reply<T>) -> Command,
    ) -> Result<T, ScannerError> {
        let _permit = self.admit_operation()?;
        let (sender, receiver) = sync_channel(1);
        self.submit(make(sender))?;
        receiver
            .recv()
            .map_err(|_| ScannerError::environment_closed("await scanner operation"))?
    }

    pub(crate) fn request_pull_cancellation(
        &self,
        session_id: u32,
        pull_id: u32,
    ) -> Result<bool, ScannerError> {
        // A pull already consumes one normal-operation permit. Cancellation is
        // an ownership/liveness boundary and must remain admissible when other
        // callers have filled the bounded ordinary-operation pool. At most one
        // pull per each of four sessions can use this path, while the separate
        // 128-command channel remains independently bounded.
        let (reply, receiver) = sync_channel(1);
        self.submit(Command::CancelPull {
            session_id,
            pull_id,
            reply,
        })?;
        receiver
            .recv()
            .map_err(|_| ScannerError::environment_closed("cancel result pull"))?
    }

    pub(crate) fn state(&self, session_id: u32) -> Result<String, ScannerError> {
        let views = lock(&self.views);
        let view = views
            .get(&session_id)
            .ok_or_else(|| ScannerError::lifecycle("read session state", "unknown scan session"))?;
        Ok(decode_state(view.state.load(Ordering::Acquire)).into())
    }

    pub(crate) fn close_scanner_background(&self, scanner_id: u32) {
        let _ = self.submit(Command::CloseScanner {
            scanner_id,
            reply: None,
        });
    }

    pub(crate) fn shutdown_and_join(&self) {
        if self.accepting.swap(false, Ordering::AcqRel) {
            let _ = self.sender.try_send(Command::Shutdown);
            wake_eventfd(&self.wake);
        }
        if let Some(thread) = lock(&self.thread).take() {
            let _ = thread.join();
        }
    }

    fn admit_operation(&self) -> Result<OperationPermit<'_>, ScannerError> {
        self.pending_operations
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_PENDING_OPERATIONS).then_some(current + 1)
            })
            .map_err(|_| {
                ScannerError::resource(
                    "submit scanner operation",
                    "too many pending scanner operations",
                )
            })?;
        Ok(OperationPermit { runtime: self })
    }
}

impl Drop for RuntimeHandle {
    fn drop(&mut self) {
        self.shutdown_and_join();
    }
}

struct OperationPermit<'a> {
    runtime: &'a RuntimeHandle,
}

impl Drop for OperationPermit<'_> {
    fn drop(&mut self) {
        self.runtime
            .pending_operations
            .fetch_sub(1, Ordering::AcqRel);
    }
}

struct ManagedSession {
    core: SessionCore,
    slot: Option<u8>,
    view: Arc<SessionView>,
    pending_pause: Vec<Reply<()>>,
    pending_cancel: Vec<Reply<NativeScanSummary>>,
    pending_summary: Vec<Reply<NativeScanSummary>>,
    pending_pull: Option<PendingPull>,
    early_cancelled_pull: Option<u32>,
    last_pull_id: u32,
}

struct PendingPull {
    id: u32,
    maximum: usize,
    ready_at: Option<Instant>,
    reply: Reply<PullResult>,
}

impl ManagedSession {
    fn update_view(&self) {
        self.view
            .state
            .store(encode_state(self.core.lifecycle()), Ordering::Release);
    }

    fn finish_waiters(&mut self) {
        self.update_view();
        if self.core.lifecycle() == SessionLifecycle::Paused {
            for reply in self.pending_pause.drain(..) {
                complete(reply, Ok(()));
            }
        }
        if let Some(mut pull) = self.pending_pull.take() {
            let available = self.core.queued_results();
            let terminal = terminal(self.core.lifecycle());
            let ready = available >= pull.maximum
                || terminal
                || pull
                    .ready_at
                    .is_some_and(|ready_at| Instant::now() >= ready_at);
            if available > 0 && ready {
                if let Some(batch) = self.core.next_batch(pull.maximum) {
                    complete(pull.reply, Ok(PullResult::Batch(Box::new(batch))));
                } else {
                    complete(
                        pull.reply,
                        Err(ScannerError::internal(
                            "pull result batch",
                            "queued result count changed during worker-owned sealing",
                        )),
                    );
                }
            } else if terminal {
                complete(pull.reply, Ok(PullResult::Terminal));
            } else {
                if available > 0 && pull.ready_at.is_none() {
                    pull.ready_at = Instant::now().checked_add(BATCH_COALESCE_DELAY);
                }
                self.pending_pull = Some(pull);
            }
        }
        if terminal(self.core.lifecycle()) {
            let summary = self.core.summary();
            *lock(&self.view.summary) = Some(summary.clone());
            for reply in self.pending_cancel.drain(..) {
                complete(reply, Ok(summary.clone()));
            }
            for reply in self.pending_summary.drain(..) {
                complete(reply, Ok(summary.clone()));
            }
        }
    }

    fn close(mut self) -> (Option<u8>, NativeScanSummary) {
        self.core.close();
        self.update_view();
        let summary = self.core.summary();
        *lock(&self.view.summary) = Some(summary.clone());
        for reply in self.pending_pause.drain(..) {
            complete(
                reply,
                Err(ScannerError::lifecycle(
                    "pause session",
                    "session was closed",
                )),
            );
        }
        for reply in self.pending_cancel.drain(..) {
            complete(reply, Ok(summary.clone()));
        }
        for reply in self.pending_summary.drain(..) {
            complete(reply, Ok(summary.clone()));
        }
        if let Some(pull) = self.pending_pull.take() {
            complete(pull.reply, Ok(PullResult::Terminal));
        }
        (self.slot.take(), summary)
    }
}

struct WorkerState {
    context: Option<RouteContext>,
    context_error: Option<ScannerError>,
    context_snapshot: Option<NetworkSnapshot>,
    scanners: Vec<u32>,
    sessions: HashMap<u32, ManagedSession>,
    free_slots: VecDeque<u8>,
    next_session_id: u32,
    views: Arc<Mutex<HashMap<u32, Arc<SessionView>>>>,
}

impl WorkerState {
    fn new(views: Arc<Mutex<HashMap<u32, Arc<SessionView>>>>) -> Self {
        let context = RouteContext::new().and_then(|mut value| {
            let snapshot = value.snapshot()?;
            Ok((value, snapshot))
        });
        let (context, context_error, context_snapshot) = match context {
            Ok((value, snapshot)) => (Some(value), None, Some(snapshot)),
            Err(error) => (
                None,
                Some(ScannerError::context(
                    "initialize network context",
                    error.to_string(),
                )),
                None,
            ),
        };
        Self {
            context,
            context_error,
            context_snapshot,
            scanners: Vec::new(),
            sessions: HashMap::new(),
            free_slots: VecDeque::from([0, 1, 2, 3]),
            next_session_id: 1,
            views,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "bounded command dispatch keeps every reply and lifecycle transition exhaustive"
    )]
    fn command(&mut self, command: Command) -> bool {
        match command {
            Command::RegisterScanner { scanner_id, reply } => {
                let result = if self.scanners.len() >= MAX_SCANNERS {
                    Err(ScannerError::resource(
                        "create scanner",
                        "at most four scanner objects may exist in one Node environment",
                    ))
                } else if let Some(error) = self.context_error.clone() {
                    Err(error)
                } else {
                    self.scanners.push(scanner_id);
                    Ok(())
                };
                complete(reply, result);
            }
            Command::Start {
                scanner_id,
                plan,
                reply,
            } => self.start(scanner_id, *plan, reply),
            Command::Pause { session_id, reply } => {
                if let Some(session) = self.sessions.get_mut(&session_id) {
                    match session.core.request_pause() {
                        Ok(()) => session.pending_pause.push(reply),
                        Err(error) => complete(reply, Err(error)),
                    }
                } else {
                    complete(reply, Err(unknown_session("pause session")));
                }
            }
            Command::Resume { session_id, reply } => {
                let result = self
                    .sessions
                    .get_mut(&session_id)
                    .ok_or_else(|| unknown_session("resume session"))
                    .and_then(|session| session.core.resume());
                complete(reply, result);
            }
            Command::Cancel { session_id, reply } => {
                if let Some(session) = self.sessions.get_mut(&session_id) {
                    match session.core.cancel() {
                        Ok(()) => session.pending_cancel.push(reply),
                        Err(error) => complete(reply, Err(error)),
                    }
                } else if let Some(summary) = cached_summary(&self.views, session_id) {
                    complete(reply, Ok(summary));
                } else {
                    complete(reply, Err(unknown_session("cancel session")));
                }
            }
            Command::Pull {
                session_id,
                pull_id,
                maximum,
                reply,
            } => {
                if let Some(session) = self.sessions.get_mut(&session_id) {
                    if pull_id == 0 || pull_id <= session.last_pull_id {
                        complete(
                            reply,
                            Err(ScannerError::lifecycle(
                                "pull result batch",
                                "pull identifiers must increase and may not be reused",
                            )),
                        );
                    } else if session.pending_pull.is_some() {
                        complete(
                            reply,
                            Err(ScannerError::resource(
                                "pull result batch",
                                "only one nextBatch operation may be pending",
                            )),
                        );
                    } else if session.early_cancelled_pull == Some(pull_id) {
                        session.early_cancelled_pull = None;
                        session.last_pull_id = pull_id;
                        complete(reply, Ok(PullResult::Aborted));
                    } else if let Some(batch) = session.core.next_batch(maximum) {
                        session.last_pull_id = pull_id;
                        complete(reply, Ok(PullResult::Batch(Box::new(batch))));
                    } else if terminal(session.core.lifecycle()) {
                        session.last_pull_id = pull_id;
                        complete(reply, Ok(PullResult::Terminal));
                    } else {
                        session.last_pull_id = pull_id;
                        session.pending_pull = Some(PendingPull {
                            id: pull_id,
                            maximum,
                            ready_at: None,
                            reply,
                        });
                    }
                } else {
                    complete(reply, Ok(PullResult::Terminal));
                }
            }
            Command::CancelPull {
                session_id,
                pull_id,
                reply,
            } => {
                let cancelled = if let Some(session) = self.sessions.get_mut(&session_id) {
                    if session.pending_pull.as_ref().map(|value| value.id) == Some(pull_id) {
                        if let Some(pull) = session.pending_pull.take() {
                            complete(pull.reply, Ok(PullResult::Aborted));
                            true
                        } else {
                            false
                        }
                    } else if pull_id > session.last_pull_id
                        && session.early_cancelled_pull.is_none()
                    {
                        session.early_cancelled_pull = Some(pull_id);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };
                complete(reply, Ok(cancelled));
            }
            Command::Progress { session_id, reply } => {
                if let Some(session) = self.sessions.get_mut(&session_id) {
                    complete(reply, Ok(session.core.progress()));
                } else if let Some(summary) = cached_summary(&self.views, session_id) {
                    complete(reply, Ok(summary.progress));
                } else {
                    complete(reply, Err(unknown_session("read session progress")));
                }
            }
            Command::Summary { session_id, reply } => {
                if let Some(session) = self.sessions.get_mut(&session_id) {
                    if terminal(session.core.lifecycle()) {
                        complete(reply, Ok(session.core.summary()));
                    } else {
                        session.pending_summary.push(reply);
                    }
                } else if let Some(summary) = cached_summary(&self.views, session_id) {
                    complete(reply, Ok(summary));
                } else {
                    complete(reply, Err(unknown_session("read session summary")));
                }
            }
            Command::CloseSession { session_id, reply } => {
                if let Some(session) = self.sessions.remove(&session_id)
                    && let Some(slot) = session.close().0
                {
                    self.free_slots.push_back(slot);
                }
                complete(reply, Ok(()));
            }
            Command::CloseScanner { scanner_id, reply } => {
                self.close_scanner(scanner_id);
                if let Some(reply) = reply {
                    complete(reply, Ok(()));
                }
            }
            Command::Shutdown => return true,
        }
        false
    }

    fn start(&mut self, scanner_id: u32, plan: ValidatedPlan, reply: Reply<u32>) {
        if !self.scanners.contains(&scanner_id) {
            complete(
                reply,
                Err(ScannerError::lifecycle(
                    "start session",
                    "scanner is closed",
                )),
            );
            return;
        }
        let active = self
            .sessions
            .values()
            .filter(|session| !terminal(session.core.lifecycle()))
            .count();
        if active >= MAX_SESSIONS {
            complete(
                reply,
                Err(ScannerError::resource(
                    "start session",
                    "at most four scan sessions may run in one Node environment",
                )),
            );
            return;
        }
        let Some(slot) = self.free_slots.pop_front() else {
            complete(
                reply,
                Err(ScannerError::resource(
                    "start session",
                    "no session slot available",
                )),
            );
            return;
        };
        let id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);
        if id == 0 || self.next_session_id == 0 {
            self.free_slots.push_back(slot);
            complete(
                reply,
                Err(ScannerError::resource(
                    "start session",
                    "session identifier space exhausted",
                )),
            );
            return;
        }
        let Some(context) = self.context.as_mut() else {
            self.free_slots.push_back(slot);
            complete(
                reply,
                Err(self.context_error.clone().unwrap_or_else(|| {
                    ScannerError::context("start session", "network context unavailable")
                })),
            );
            return;
        };
        match SessionCore::new(id, scanner_id, slot, plan, context) {
            Ok(core) => {
                let view = Arc::new(SessionView::new(scanner_id));
                view.state
                    .store(encode_state(core.lifecycle()), Ordering::Release);
                lock(&self.views).insert(id, Arc::clone(&view));
                self.sessions.insert(
                    id,
                    ManagedSession {
                        core,
                        slot: Some(slot),
                        view,
                        pending_pause: Vec::new(),
                        pending_cancel: Vec::new(),
                        pending_summary: Vec::new(),
                        pending_pull: None,
                        early_cancelled_pull: None,
                        last_pull_id: 0,
                    },
                );
                complete(reply, Ok(id));
            }
            Err(error) => {
                self.free_slots.push_back(slot);
                complete(reply, Err(error));
            }
        }
    }

    fn drive(&mut self) {
        let Some(context) = self.context.as_mut() else {
            return;
        };
        let refresh = context.refresh();
        match refresh {
            Ok(RefreshOutcome::Published(snapshot)) => {
                self.publish_context_snapshot(snapshot);
            }
            Ok(RefreshOutcome::Unchanged { .. }) => {}
            Ok(RefreshOutcome::Backoff { .. }) => {
                let error = ScannerError::context(
                    "refresh network context",
                    "network context is waiting for a bounded resynchronization",
                );
                for session in self.sessions.values_mut() {
                    session.core.fail_context(error.clone());
                }
            }
            Err(error) => {
                let error = ScannerError::context("refresh network context", error.to_string());
                for session in self.sessions.values_mut() {
                    session.core.fail_context(error.clone());
                }
            }
        }
        let Some(context) = self.context.as_mut() else {
            return;
        };
        for session in self.sessions.values_mut() {
            if !terminal(session.core.lifecycle()) {
                session.core.drive(context);
            }
            session.finish_waiters();
            if terminal(session.core.lifecycle())
                && let Some(slot) = session.slot.take()
            {
                self.free_slots.push_back(slot);
            }
        }
        let snapshot = context.current_snapshot().cloned();
        if let Some(snapshot) = snapshot {
            self.publish_context_snapshot(snapshot);
        }
    }

    fn publish_context_snapshot(&mut self, snapshot: NetworkSnapshot) {
        let topology_changed = self.context_snapshot.as_ref().is_some_and(|old| {
            old.interfaces != snapshot.interfaces
                || old.addresses != snapshot.addresses
                || old.routes != snapshot.routes
                || old.rules != snapshot.rules
        });
        self.context_snapshot = Some(snapshot);
        if topology_changed {
            for session in self.sessions.values_mut() {
                session.core.invalidate_context();
            }
        }
    }

    fn close_scanner(&mut self, scanner_id: u32) {
        self.scanners.retain(|value| *value != scanner_id);
        let ids: Vec<u32> = self
            .sessions
            .iter()
            .filter_map(|(id, session)| (session.core.scanner_id == scanner_id).then_some(*id))
            .collect();
        for id in ids {
            if let Some(session) = self.sessions.remove(&id)
                && let Some(slot) = session.close().0
            {
                self.free_slots.push_back(slot);
            }
        }
    }

    fn shutdown(&mut self) {
        let ids = self.scanners.clone();
        for id in ids {
            self.close_scanner(id);
        }
        self.scanners.clear();
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the worker thread exclusively owns these descriptors and shutdown handles"
)]
fn run_worker(
    epoll_descriptor: OwnedFd,
    wake: Arc<OwnedFd>,
    receiver: Receiver<Command>,
    accepting: Arc<AtomicBool>,
    views: Arc<Mutex<HashMap<u32, Arc<SessionView>>>>,
) {
    let mut state = WorkerState::new(views);
    let mut events = Vec::with_capacity(8);
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: TICK_NANOSECONDS,
    };
    while accepting.load(Ordering::Acquire) {
        events.clear();
        match epoll::wait(
            &epoll_descriptor,
            spare_capacity(&mut events),
            Some(&timeout),
        ) {
            Ok(_) => {}
            Err(Errno::INTR) => continue,
            Err(_) => break,
        }
        if !events.is_empty() {
            drain_eventfd(&wake);
        }
        let mut stop = false;
        for _ in 0..COMMAND_BUDGET {
            match receiver.try_recv() {
                Ok(command) => {
                    if state.command(command) {
                        stop = true;
                        break;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    stop = true;
                    break;
                }
            }
        }
        state.drive();
        if stop {
            break;
        }
    }
    accepting.store(false, Ordering::Release);
    state.shutdown();
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "completion consumes its one-shot sender to prevent duplicate settlement"
)]
fn complete<T>(reply: Reply<T>, result: Result<T, ScannerError>) {
    let _ = reply.try_send(result);
}

fn cached_summary(
    views: &Mutex<HashMap<u32, Arc<SessionView>>>,
    session_id: u32,
) -> Option<NativeScanSummary> {
    let views = lock(views);
    lock(&views.get(&session_id)?.summary).clone()
}

fn unknown_session(operation: &'static str) -> ScannerError {
    ScannerError::lifecycle(operation, "unknown or closed scan session")
}

fn terminal(value: SessionLifecycle) -> bool {
    matches!(
        value,
        SessionLifecycle::Completed | SessionLifecycle::Failed | SessionLifecycle::Closed
    )
}

fn encode_state(value: SessionLifecycle) -> u8 {
    match value {
        SessionLifecycle::Created => 0,
        SessionLifecycle::Running => 1,
        SessionLifecycle::Pausing => 2,
        SessionLifecycle::Paused => 3,
        SessionLifecycle::Cancelling => 4,
        SessionLifecycle::Completed => 5,
        SessionLifecycle::Failed => 6,
        SessionLifecycle::Closed => 7,
    }
}

fn decode_state(value: u8) -> &'static str {
    match value {
        0 => state_name(SessionLifecycle::Created),
        1 => state_name(SessionLifecycle::Running),
        2 => state_name(SessionLifecycle::Pausing),
        3 => state_name(SessionLifecycle::Paused),
        4 => state_name(SessionLifecycle::Cancelling),
        5 => state_name(SessionLifecycle::Completed),
        6 => state_name(SessionLifecycle::Failed),
        _ => state_name(SessionLifecycle::Closed),
    }
}

fn drain_eventfd(descriptor: &OwnedFd) {
    let mut bytes = [0_u8; 8];
    while matches!(read(descriptor, &mut bytes), Ok(_) | Err(Errno::INTR)) {}
}

fn wake_eventfd(descriptor: &OwnedFd) {
    while let Err(Errno::INTR) = write(descriptor, &1_u64.to_ne_bytes()) {}
}

fn lock<T>(value: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
