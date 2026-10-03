/**
 * Error whose `name` is the class name (what `ex()` logs as error_class).
 *
 * Exported through exceptions.ts and the barrel; it lives in its own import-free module because Condition.ts
 * (ConditionError) and exceptions.ts (which imports ConditionError) both extend it, and a class defined in
 * exceptions.ts would be in its temporal dead zone whenever exceptions.ts is the first of the two to load.
 */
export class NamedError extends Error {
	override get name(): string {
		return this.constructor.name;
	}
}
