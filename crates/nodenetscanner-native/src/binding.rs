use std::sync::Arc;

use napi::bindgen_prelude::{AsyncTask, Env};
use napi::{Result, Task};
use napi_derive::napi;
use nodenet_linux_context::{NetworkSnapshot, RouteContext};

use crate::error::ScannerError;
use crate::model::{DEFAULT_BATCH_RESULTS, MAX_BATCH_RESULTS, NativeScanPlan};
use crate::runtime::{Command, RuntimeHandle};
use crate::session::{NativePullResult, NativeScanProgress, NativeScanSummary, PullResult};

struct EnvironmentRuntime {
    runtime: Arc<RuntimeHandle>,
}

#[napi(object)]
pub struct NativeNetworkInterface {
    pub index: u32,
    pub name: String,
    pub flags: u32,
    pub link_layer_type: u32,
    pub mtu: Option<u32>,
    pub hardware_address: Vec<u8>,
    pub link_kind: Option<String>,
}

#[napi(object)]
pub struct NativeNetworkAddress {
    pub interface_index: u32,
    pub family: u32,
    pub prefix_length: u32,
    pub address: Option<String>,
    pub local: Option<String>,
}

#[napi(object)]
pub struct NativeNetworkRoute {
    pub family: u32,
    pub destination: Option<String>,
    pub prefix_length: u32,
    pub gateway: Option<String>,
    pub preferred_source: Option<String>,
    pub interface_index: Option<u32>,
    pub table: u32,
    pub route_type: u32,
}

#[napi(object)]
pub struct NativeNetworkContextSnapshot {
    pub generation: String,
    pub netns_cookie: Option<String>,
    pub interfaces: Vec<NativeNetworkInterface>,
    pub addresses: Vec<NativeNetworkAddress>,
    pub routes: Vec<NativeNetworkRoute>,
    pub rule_count: u32,
    pub neighbor_count: u32,
}

#[napi]
pub struct NativeScanner {
    runtime: Arc<RuntimeHandle>,
    id: u32,
}

#[napi]
impl NativeScanner {
    #[napi]
    pub fn ready(&self) -> AsyncTask<ReadyTask> {
        AsyncTask::new(ReadyTask {
            runtime: Arc::clone(&self.runtime),
            scanner_id: self.id,
        })
    }

    #[napi]
    pub fn start(&self, plan: NativeScanPlan) -> AsyncTask<StartTask> {
        AsyncTask::new(StartTask {
            runtime: Arc::clone(&self.runtime),
            scanner_id: self.id,
            plan: Some(plan),
        })
    }

    #[napi]
    pub fn pause(&self, session_id: u32) -> AsyncTask<PauseTask> {
        AsyncTask::new(PauseTask {
            runtime: Arc::clone(&self.runtime),
            session_id,
        })
    }

    #[napi]
    pub fn resume(&self, session_id: u32) -> AsyncTask<ResumeTask> {
        AsyncTask::new(ResumeTask {
            runtime: Arc::clone(&self.runtime),
            session_id,
        })
    }

    #[napi]
    pub fn cancel(&self, session_id: u32) -> AsyncTask<CancelTask> {
        AsyncTask::new(CancelTask {
            runtime: Arc::clone(&self.runtime),
            session_id,
        })
    }

    #[napi]
    pub fn next_batch(
        &self,
        session_id: u32,
        pull_id: u32,
        maximum: Option<u32>,
    ) -> Result<AsyncTask<PullTask>> {
        let maximum = maximum.unwrap_or(DEFAULT_BATCH_RESULTS);
        if maximum == 0 || maximum > MAX_BATCH_RESULTS {
            return Err(ScannerError::invalid(
                "pull result batch",
                "maxResults must be from 1 through 4096",
            )
            .into_napi());
        }
        Ok(AsyncTask::new(PullTask {
            runtime: Arc::clone(&self.runtime),
            session_id,
            pull_id,
            maximum: usize::try_from(maximum).unwrap_or(usize::MAX),
        }))
    }

    #[napi]
    pub fn cancel_pull(&self, session_id: u32, pull_id: u32) -> AsyncTask<CancelPullTask> {
        AsyncTask::new(CancelPullTask {
            runtime: Arc::clone(&self.runtime),
            session_id,
            pull_id,
        })
    }

    #[napi]
    pub fn progress(&self, session_id: u32) -> AsyncTask<ProgressTask> {
        AsyncTask::new(ProgressTask {
            runtime: Arc::clone(&self.runtime),
            session_id,
        })
    }

    #[napi]
    pub fn summary(&self, session_id: u32) -> AsyncTask<SummaryTask> {
        AsyncTask::new(SummaryTask {
            runtime: Arc::clone(&self.runtime),
            session_id,
        })
    }

    #[napi]
    pub fn close_session(&self, session_id: u32) -> AsyncTask<CloseSessionTask> {
        AsyncTask::new(CloseSessionTask {
            runtime: Arc::clone(&self.runtime),
            session_id,
        })
    }

    #[napi]
    pub fn state(&self, session_id: u32) -> Result<String> {
        self.runtime
            .state(session_id)
            .map_err(ScannerError::into_napi)
    }

    #[napi]
    pub fn close(&self) -> AsyncTask<CloseScannerTask> {
        AsyncTask::new(CloseScannerTask {
            runtime: Arc::clone(&self.runtime),
            scanner_id: self.id,
        })
    }
}

impl Drop for NativeScanner {
    fn drop(&mut self) {
        self.runtime.close_scanner_background(self.id);
    }
}

#[napi]
pub fn create_native_scanner(env: Env) -> Result<NativeScanner> {
    let runtime = environment_runtime(env)?;
    let id = runtime
        .allocate_scanner_id()
        .map_err(ScannerError::into_napi)?;
    Ok(NativeScanner { runtime, id })
}

#[napi]
pub fn inspect_network_context() -> AsyncTask<InspectTask> {
    AsyncTask::new(InspectTask)
}

pub struct InspectTask;

impl Task for InspectTask {
    type Output = NativeNetworkContextSnapshot;
    type JsValue = NativeNetworkContextSnapshot;

    fn compute(&mut self) -> Result<Self::Output> {
        let mut context = RouteContext::new().map_err(|error| {
            ScannerError::context("inspect network context", error.to_string()).into_napi()
        })?;
        let snapshot = context.snapshot().map_err(|error| {
            ScannerError::context("inspect network context", error.to_string()).into_napi()
        })?;
        Ok(native_snapshot(snapshot))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct ReadyTask {
    runtime: Arc<RuntimeHandle>,
    scanner_id: u32,
}

impl Task for ReadyTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> Result<Self::Output> {
        self.runtime
            .request(|reply| Command::RegisterScanner {
                scanner_id: self.scanner_id,
                reply,
            })
            .map_err(ScannerError::into_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct StartTask {
    runtime: Arc<RuntimeHandle>,
    scanner_id: u32,
    plan: Option<NativeScanPlan>,
}

impl Task for StartTask {
    type Output = u32;
    type JsValue = u32;

    fn compute(&mut self) -> Result<Self::Output> {
        let plan = self
            .plan
            .take()
            .ok_or_else(|| {
                ScannerError::internal("start session", "scan plan already consumed").into_napi()
            })?
            .validate()
            .map_err(ScannerError::into_napi)?;
        self.runtime
            .request(|reply| Command::Start {
                scanner_id: self.scanner_id,
                plan: Box::new(plan),
                reply,
            })
            .map_err(ScannerError::into_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

macro_rules! unit_task {
    ($name:ident, $variant:ident) => {
        pub struct $name {
            runtime: Arc<RuntimeHandle>,
            session_id: u32,
        }

        impl Task for $name {
            type Output = ();
            type JsValue = ();

            fn compute(&mut self) -> Result<Self::Output> {
                self.runtime
                    .request(|reply| Command::$variant {
                        session_id: self.session_id,
                        reply,
                    })
                    .map_err(ScannerError::into_napi)
            }

            fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
                Ok(output)
            }
        }
    };
}

unit_task!(PauseTask, Pause);
unit_task!(ResumeTask, Resume);
unit_task!(CloseSessionTask, CloseSession);

pub struct CancelTask {
    runtime: Arc<RuntimeHandle>,
    session_id: u32,
}

impl Task for CancelTask {
    type Output = NativeScanSummary;
    type JsValue = NativeScanSummary;

    fn compute(&mut self) -> Result<Self::Output> {
        self.runtime
            .request(|reply| Command::Cancel {
                session_id: self.session_id,
                reply,
            })
            .map_err(ScannerError::into_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct SummaryTask {
    runtime: Arc<RuntimeHandle>,
    session_id: u32,
}

impl Task for SummaryTask {
    type Output = NativeScanSummary;
    type JsValue = NativeScanSummary;

    fn compute(&mut self) -> Result<Self::Output> {
        self.runtime
            .request(|reply| Command::Summary {
                session_id: self.session_id,
                reply,
            })
            .map_err(ScannerError::into_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct PullTask {
    runtime: Arc<RuntimeHandle>,
    session_id: u32,
    pull_id: u32,
    maximum: usize,
}

impl Task for PullTask {
    type Output = PullResult;
    type JsValue = NativePullResult;

    fn compute(&mut self) -> Result<Self::Output> {
        self.runtime
            .request(|reply| Command::Pull {
                session_id: self.session_id,
                pull_id: self.pull_id,
                maximum: self.maximum,
                reply,
            })
            .map_err(ScannerError::into_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(NativePullResult::from_pull(output))
    }
}

pub struct CancelPullTask {
    runtime: Arc<RuntimeHandle>,
    session_id: u32,
    pull_id: u32,
}

impl Task for CancelPullTask {
    type Output = bool;
    type JsValue = bool;

    fn compute(&mut self) -> Result<Self::Output> {
        self.runtime
            .request_pull_cancellation(self.session_id, self.pull_id)
            .map_err(ScannerError::into_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct ProgressTask {
    runtime: Arc<RuntimeHandle>,
    session_id: u32,
}

impl Task for ProgressTask {
    type Output = NativeScanProgress;
    type JsValue = NativeScanProgress;

    fn compute(&mut self) -> Result<Self::Output> {
        self.runtime
            .request(|reply| Command::Progress {
                session_id: self.session_id,
                reply,
            })
            .map_err(ScannerError::into_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct CloseScannerTask {
    runtime: Arc<RuntimeHandle>,
    scanner_id: u32,
}

impl Task for CloseScannerTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> Result<Self::Output> {
        self.runtime
            .request(|reply| Command::CloseScanner {
                scanner_id: self.scanner_id,
                reply: Some(reply),
            })
            .map_err(ScannerError::into_napi)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

fn environment_runtime(env: Env) -> Result<Arc<RuntimeHandle>> {
    if let Some(instance) = env.get_instance_data::<EnvironmentRuntime>()? {
        return Ok(Arc::clone(&instance.runtime));
    }
    let runtime = RuntimeHandle::start().map_err(ScannerError::into_napi)?;
    env.add_async_cleanup_hook(Arc::clone(&runtime), |runtime| {
        runtime.shutdown_and_join();
    })?;
    env.set_instance_data(
        EnvironmentRuntime {
            runtime: Arc::clone(&runtime),
        },
        (),
        |context| context.value.runtime.shutdown_and_join(),
    )?;
    Ok(runtime)
}

fn native_snapshot(snapshot: NetworkSnapshot) -> NativeNetworkContextSnapshot {
    NativeNetworkContextSnapshot {
        generation: snapshot.generation.to_string(),
        netns_cookie: snapshot.netns_cookie.map(|value| value.to_string()),
        interfaces: snapshot
            .interfaces
            .into_iter()
            .map(|value| NativeNetworkInterface {
                index: value.index,
                name: value.name,
                flags: value.flags,
                link_layer_type: u32::from(value.link_layer_type),
                mtu: value.mtu,
                hardware_address: value.hardware_address,
                link_kind: value.link_kind,
            })
            .collect(),
        addresses: snapshot
            .addresses
            .into_iter()
            .map(|value| NativeNetworkAddress {
                interface_index: value.interface_index,
                family: u32::from(value.family),
                prefix_length: u32::from(value.prefix_length),
                address: value.address.map(|address| address.to_string()),
                local: value.local.map(|address| address.to_string()),
            })
            .collect(),
        routes: snapshot
            .routes
            .into_iter()
            .map(|value| NativeNetworkRoute {
                family: u32::from(value.family),
                destination: value.destination.map(|address| address.to_string()),
                prefix_length: u32::from(value.destination_prefix_length),
                gateway: value.gateway.map(|address| address.to_string()),
                preferred_source: value.preferred_source.map(|address| address.to_string()),
                interface_index: value.output_interface,
                table: value.table,
                route_type: u32::from(value.route_type),
            })
            .collect(),
        rule_count: u32::try_from(snapshot.rules.len()).unwrap_or(u32::MAX),
        neighbor_count: u32::try_from(snapshot.neighbors.len()).unwrap_or(u32::MAX),
    }
}
