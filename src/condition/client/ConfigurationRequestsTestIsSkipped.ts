import { AbstractCondition, type Environment } from "../../framework/index.ts";

export class ConfigurationRequestsTestIsSkipped extends AbstractCondition {
	override evaluate(_env: Environment): Environment {
		throw this.error(
			"JSON configuration contains 'skip_test: true'; not running test. System under test cannot be certified.",
		);
	}
}
