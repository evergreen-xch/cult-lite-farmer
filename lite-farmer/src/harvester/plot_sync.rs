use crate::harvester::plot_manager::PlotManager;
use dg_xch_utils::clients::protocols::harvester::PlotSyncResponse;
use dg_xch_utils::clients::websocket::Client;
use std::io::Error;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

type SyncTask = Arc<Mutex<Option<JoinHandle<Result<(), Error>>>>>;

pub struct PlotSyncSender {
    _plot_manager: Arc<Mutex<PlotManager>>,
    _connection: Option<Arc<Mutex<Client>>>,
    _sync_id: Arc<Mutex<u64>>,
    _next_message_id: Arc<Mutex<u64>>,
    _messages: Arc<Mutex<Vec<Message>>>,
    _last_sync_id: Arc<Mutex<u64>>,
    _stop_requested: Arc<Mutex<bool>>,
    _task: SyncTask,
    _response: Arc<Mutex<Option<PlotSyncResponse>>>,
}
impl PlotSyncSender {
    pub fn new(plot_manager: Arc<Mutex<PlotManager>>) -> Self {
        PlotSyncSender {
            _plot_manager: plot_manager,
            _connection: None,
            _sync_id: Arc::new(Mutex::new(0)),
            _next_message_id: Arc::new(Mutex::new(0)),
            _messages: Arc::new(Mutex::new(vec![])),
            _last_sync_id: Arc::new(Mutex::new(0)),
            _stop_requested: Arc::new(Mutex::new(false)),
            _task: Arc::new(Mutex::new(None)),
            _response: Arc::new(Mutex::new(None)),
        }
    }
    // pub async fn start(mut self) -> Result<(), Error> {
    //     let task_exists = self.task.lock().await.is_some();
    //     if !task_exists && *self.stop_requested.lock().await{
    //         self.await_closed().await
    //     } else if !task_exists {
    //         *self.task.lock().await = Some(tokio::spawn( Self::run(
    //             self.stop_requested.clone(),
    //             self.sync_id.clone(),
    //             self.connection.clone(),
    //             self.messages.clone(),
    //         )));
    //         Ok(())
    //     } else {
    //         Err(Error::new(ErrorKind::AlreadyExists, "Already Started"))
    //     }
    // }
    // pub async fn stop(&mut self) {
    //     *self.stop_requested.lock().await = true;
    // }
    // pub async fn await_closed(&mut self) -> Result<(), Error> {
    //     if let Some(task) = self.task.lock().await.as_mut() {
    //         let _ = task.await;
    //     }
    //     self.task = Arc::new(Mutex::new(None));
    //     self.reset().await;
    //     *self.stop_requested.lock().await = false;
    //     Ok(())
    // }
    // pub async fn set_connection(&mut self, peer: Arc<Mutex<Client>>) {
    //     self.connection = Some(peer);
    // }
    // pub async fn bump_next_message_id(&mut self) {
    //     let cur;
    //     {
    //         cur = *self.next_message_id.lock().await;
    //     }
    //     *self.next_message_id.lock().await = cur + 1;
    // }
    // pub async fn reset(&mut self) {
    //     self.last_sync_id =Arc::new(Mutex::new(0));
    //     self.sync_id = Arc::new(Mutex::new(0));
    //     self.next_message_id = Arc::new(Mutex::new(0));
    //     self.messages.lock().await.clear();
    //     let mut task = self.task.lock().await;
    //     if let Some(_task) = task.as_mut() {
    //         //self.sync_start(self.plot_manager.lock().await.plot_count(), true).await;
    //         for (_remaining,_batch) in self.plot_manager.lock().await.plots.iter() {
    //
    //         }
    //     }
    // }
    // pub async fn run(
    //     stop_requested: Arc<Mutex<bool>>,
    //     sync_id: Arc<Mutex<u64>>,
    //     connection: Option<Arc<Mutex<Client>>>,
    //     messages: Arc<Mutex<Vec<Message>>>,
    // ) -> Result<(), Error> {
    //     loop {
    //         if *stop_requested.lock().await {
    //             break;
    //         }
    //         if connection.is_none() || *sync_id.lock().await == 0 {
    //             tokio::time::sleep(Duration::from_millis(100)).await;
    //             continue;
    //         } else if let Some(con) = &connection {
    //             if *sync_id.lock().await != 0 {
    //                 if let Some(msg) = messages.lock().await.pop() {
    //                     let _ = con.lock().await.send(msg).await;
    //                 }
    //             }
    //         }
    //     }
    //     Ok(())
    // }
}
