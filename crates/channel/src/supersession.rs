use crate::model;
use release_channel_index::client;
use release_channel_index::model as index;

/// Independently configured authority and retained committed channel context.
pub struct Context<'a> {
    pub pin: &'a model::Id,
    pub namespace: &'a index::Namespace,
    pub minimum_revision: u64,
    pub predecessor: model::State,
}

/// Authenticated resolved-orphan high-water, never caller-asserted permission to skip.
#[derive(Clone, Debug)]
pub struct Supersession {
    predecessor: model::State,
    highest: index::Claim,
    namespace: index::Namespace,
    revision: u64,
}

impl Supersession {
    pub fn verify(
        context: &Context<'_>,
        query: &index::Request,
        reply: &index::SignedReply,
    ) -> Result<Self, model::Error> {
        if query.namespace != *context.namespace
            || !matches!(query.operation, index::Operation::Query)
        {
            return Err(model::Error::Authentication);
        }
        let snapshot = client::verify_reply(context.pin, query, reply, context.minimum_revision)
            .map_err(|_| model::Error::Authentication)?;
        let committed = snapshot
            .committed
            .as_ref()
            .ok_or(model::Error::MissingState)?;
        let highest = snapshot
            .highest
            .as_ref()
            .ok_or(model::Error::MissingState)?;
        if snapshot.pending.is_some()
            || committed.generation != context.predecessor.generation
            || committed.digest != context.predecessor.metadata
            || highest.generation <= committed.generation
            || highest.predecessor != Some(committed.digest)
        {
            return Err(model::Error::Conflict);
        }
        Ok(Self {
            predecessor: context.predecessor,
            highest: highest.clone(),
            namespace: query.namespace.clone(),
            revision: snapshot.revision,
        })
    }

    pub fn namespace(&self) -> &index::Namespace {
        &self.namespace
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn highest(&self) -> &index::Claim {
        &self.highest
    }

    pub(crate) fn permits(&self, metadata: &model::Metadata) -> bool {
        metadata.prior == Some(self.predecessor)
            && metadata.channel == self.predecessor.channel
            && metadata.generation > self.highest.generation
    }
}
