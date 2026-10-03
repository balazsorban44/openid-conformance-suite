import { AbstractCondition, args, type Environment } from "../../framework/index.ts";

export abstract class AbstractUpdatedAtValid extends AbstractCondition {
	private timeSkewMillis = 5 * 60 * 1000; // 5 minute allowable skew for testing

	protected validateUpdatedAt(env: Environment, location: string): Environment {
		const now = Date.now();
		const updatedAt = env.getLong(location, "updated_at");

		// a relatively arbitrary choice, but if the updated_at data is prior to 1990 then it seems impossible that
		// it's valid as it would predate 'the web'.
		const instantAtJan1990 = Date.UTC(1990, 0, 1);
		if (updatedAt == null) {
			this.log(location + " response does not contain 'updated_at'");
			return env;
		}

		if (now + this.timeSkewMillis < updatedAt * 1000) {
			throw this.error(
				"updated_at in " + location + " appears to be in the future",
				args("updated_at", new Date(updatedAt * 1000), "now", new Date(now)),
			);
		}
		if (instantAtJan1990 > updatedAt * 1000) {
			throw this.error(
				"updated_at in " + location + " appears to be prior to the year 1990",
				args("updated_at", new Date(updatedAt * 1000), "now", new Date(now)),
			);
		}

		this.logSuccess(
			"'updated_at' in " + location + " response seems to be a valid time",
			args("updated_at", new Date(updatedAt * 1000), "now", new Date(now)),
		);

		return env;
	}
}
