use crate::errors::CallDataBuilderError;
use crate::types::noir_call_data::NoirCallDataInputs;

mod errors;
mod types;

pub struct CallDataBuilder {}

impl CallDataBuilder {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn build_noir_register_call_data(
        &self,
        inputs: &NoirCallDataInputs,
    ) -> Result<Vec<u8>, CallDataBuilderError> {
        todo!()
    }
}
