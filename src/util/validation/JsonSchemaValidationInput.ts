import type { JsonObject } from "../../framework/json.ts";

export class JsonSchemaValidationInput {
	private inputName: string;

	private schemaResource: string;

	private jsonObject: JsonObject | null;

	constructor(inputName: string, schemaResource: string, jsonObject: JsonObject | null) {
		this.inputName = inputName;
		this.schemaResource = schemaResource;
		this.jsonObject = jsonObject;
	}

	getInputName(): string {
		return this.inputName;
	}

	setInputName(inputName: string): void {
		this.inputName = inputName;
	}

	getSchemaResource(): string {
		return this.schemaResource;
	}

	setSchemaResource(schemaResource: string): void {
		this.schemaResource = schemaResource;
	}

	getJsonObject(): JsonObject | null {
		return this.jsonObject;
	}

	setJsonObject(jsonObject: JsonObject | null): void {
		this.jsonObject = jsonObject;
	}
}
