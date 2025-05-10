use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event as CrosstermEvent};

/// Terminal events handler
pub struct Events {
    /// Event receiver channel
    rx: mpsc::Receiver<CrosstermEvent>,
    /// Event sender channel
    _tx: mpsc::Sender<CrosstermEvent>,
}

impl Events {
    /// Constructs a new instance of Events with the specified tick rate
    pub fn new(tick_rate: u64) -> Self {
        let tick_rate = Duration::from_millis(tick_rate);
        let (tx, rx) = mpsc::channel();

        let event_tx = tx.clone();
        thread::spawn(move || {
            let mut last_tick = Instant::now();
            loop {
                let timeout = tick_rate
                    .checked_sub(last_tick.elapsed())
                    .unwrap_or_else(|| Duration::from_secs(0));

                if event::poll(timeout).unwrap() {
                    if let Ok(event) = event::read() {
                        if event_tx.send(event).is_err() {
                            break;
                        }
                    }
                }

                if last_tick.elapsed() >= tick_rate {
                    last_tick = Instant::now();
                }
            }
        });

        Self { rx, _tx: tx }
    }

    /// Attempts to read an event
    pub fn next(&self) -> Result<CrosstermEvent, mpsc::RecvError> {
        self.rx.recv()
    }
}
