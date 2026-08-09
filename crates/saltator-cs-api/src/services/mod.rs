//! Domain services: protocol logic with no HTTP in it. Routes stay thin
//! — parse, call a service, shape the response — so the logic here is
//! testable without a router or client (roadmap step 2; the standing
//! rule is that route files gain no *new* domain logic, and existing
//! logic moves here when touched).

pub(crate) mod admin;
pub(crate) mod e2ee;
