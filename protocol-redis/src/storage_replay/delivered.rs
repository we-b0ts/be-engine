//! Live Redis write receipts, indexed by the locations each mutation can cover.
use std::{collections::HashMap, collections::hash_map::Entry};

use bytes::Bytes;
use tokio::time::Instant;
use traffic_protocol::connection::Endpoint;

use super::Location;

type Order = (Instant, usize);

pub struct Receipt {
    pub completed_at: Instant,
    pub index: usize,
    pub argument: Option<usize>,
    pub value: Option<Bytes>,
}

impl Receipt {
    fn order(&self) -> Order {
        (self.completed_at, self.index)
    }
}

#[derive(Default)]
pub struct State {
    case: HashMap<Endpoint, Receipts>,
    run: HashMap<Endpoint, Receipts>,
}

impl State {
    pub fn publish(
        &mut self,
        endpoint: &Endpoint,
        is_case: bool,
        location: &Location,
        receipt: Receipt,
    ) {
        let path = path(location);
        let order = receipt.order();
        if is_case {
            if self
                .run
                .get(endpoint)
                .and_then(|root| root.latest(path.clone()))
                .is_some_and(|run| run.order() >= order)
            {
                return;
            }
            publish_scope(&mut self.case, endpoint, path, receipt);
        } else if publish_scope(&mut self.run, endpoint, path.clone(), receipt)
            && let Some(root) = self.case.get_mut(endpoint)
            && !root.erase_at(path, order)
        {
            self.case.remove(endpoint);
        }
    }

    pub fn latest(&self, endpoint: &Endpoint, location: &Location) -> Option<&Receipt> {
        let path = path(location);
        [self.case.get(endpoint), self.run.get(endpoint)]
            .into_iter()
            .flatten()
            .filter_map(|root| root.latest(path.clone()))
            .max_by_key(|receipt| receipt.order())
    }

    pub fn clear_case(&mut self) {
        self.case.clear();
    }
}

fn publish_scope(
    scope: &mut HashMap<Endpoint, Receipts>,
    endpoint: &Endpoint,
    path: impl Iterator<Item = Part>,
    receipt: Receipt,
) -> bool {
    let root = match scope.get_mut(endpoint) {
        Some(root) => root,
        None => scope.entry(endpoint.clone()).or_default(),
    };
    root.publish(path, receipt)
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum Part {
    Database(i64),
    Key(Bytes),
    String,
    Hash,
    Field(Bytes),
}

fn path(location: &Location) -> impl Iterator<Item = Part> + Clone {
    let (database, key, kind, field) = match location {
        Location::Endpoint => (None, None, None, None),
        Location::Database(database) => (Some(*database), None, None, None),
        Location::Key(database, key) => (Some(*database), Some(key), None, None),
        Location::String(database, key) => (Some(*database), Some(key), Some(Part::String), None),
        Location::Hash(database, key) => (Some(*database), Some(key), Some(Part::Hash), None),
        Location::Field(database, key, field) => {
            (Some(*database), Some(key), Some(Part::Hash), Some(field))
        }
    };
    [
        database.map(Part::Database),
        key.cloned().map(Part::Key),
        kind,
        field.cloned().map(Part::Field),
    ]
    .into_iter()
    .flatten()
}

#[derive(Default)]
struct Receipts {
    at_location: Option<Receipt>,
    children: Option<Box<Children>>,
}

struct Children {
    receipts: HashMap<Part, Receipts>,
    // An upper bound stays valid when an invalidation removes a subtree.
    upper_order: Order,
}

impl Receipts {
    fn publish(&mut self, mut path: impl Iterator<Item = Part>, receipt: Receipt) -> bool {
        let order = receipt.order();
        if self
            .at_location
            .as_ref()
            .is_some_and(|current| current.order() >= order)
        {
            return false;
        }
        if let Some(part) = path.next() {
            let children = self.children.get_or_insert_with(|| {
                Box::new(Children {
                    receipts: HashMap::new(),
                    upper_order: order,
                })
            });
            if !children
                .receipts
                .entry(part)
                .or_default()
                .publish(path, receipt)
            {
                return false;
            }
            children.upper_order = children.upper_order.max(order);
        } else {
            self.prune_children(order);
            self.at_location = Some(receipt);
        }
        true
    }

    fn latest(&self, path: impl Iterator<Item = Part>) -> Option<&Receipt> {
        let mut current = self;
        let mut newest = current.at_location.as_ref();
        for part in path {
            let Some(child) = current
                .children
                .as_ref()
                .and_then(|children| children.receipts.get(&part))
            else {
                break;
            };
            current = child;
            newest = newest
                .into_iter()
                .chain(child.at_location.as_ref())
                .max_by_key(|receipt| receipt.order());
        }
        newest
    }

    fn erase_at(&mut self, mut path: impl Iterator<Item = Part>, cutoff: Order) -> bool {
        let Some(part) = path.next() else {
            return self.retain_after(cutoff);
        };
        if let Some(children) = &mut self.children {
            if let Entry::Occupied(mut child) = children.receipts.entry(part)
                && !child.get_mut().erase_at(path, cutoff)
            {
                child.remove();
            }
            if children.receipts.is_empty() {
                self.children = None;
            }
        }
        self.at_location.is_some() || self.children.is_some()
    }

    fn retain_after(&mut self, cutoff: Order) -> bool {
        if let Some(receipt) = &self.at_location {
            if receipt.order() > cutoff {
                return true;
            }
            self.at_location = None;
        }
        self.prune_children(cutoff);
        self.children.is_some()
    }

    fn prune_children(&mut self, cutoff: Order) {
        let Some(children) = &mut self.children else {
            return;
        };
        if children.upper_order <= cutoff {
            self.children = None;
            return;
        }
        children
            .receipts
            .retain(|_, child| child.retain_after(cutoff));
        if children.receipts.is_empty() {
            self.children = None;
        }
    }
}

#[cfg(test)]
mod tests;
