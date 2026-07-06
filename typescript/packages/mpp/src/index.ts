// Shared types and method definition
export * from './constants.js';
export { charge, session, subscription } from './Methods.js';
// Value-level guard for challenge-bound strings (description, realm) that cross
// into mppx's raw WWW-Authenticate serializer: rejects CR/LF and escapes
// quote/backslash so the emitted header round-trips.
export { guardChallengeValue } from './shared/challenge-guard.js';
export {
    assertPeriodHoursInRange,
    deriveSubscriptionAuthorityPda,
    deriveSubscriptionPda,
    mapSubscriptionPeriodToHours,
} from './shared/subscription.js';
