import { expect, test } from "vitest";
import type { IncomingRequest } from "../suite/server.ts";
import { clientIdOfTokenRequest } from "./token.ts";

const request = (headers: Record<string, string>, form?: Record<string, string>): IncomingRequest => ({
	headers,
	query_string_params: {},
	method: "POST",
	request_url: "https://op/token",
	path: "token",
	body_form_params: form,
});

const basic = (user: string) => ({ authorization: "Basic " + Buffer.from(`${user}:secret`).toString("base64") });

test("the client of a token request: the form-urlencoded Basic user (a '+' is a space), else client_id", () => {
	expect(clientIdOfTokenRequest(request(basic("client_OJtz%3D%5B+%3D%5C")))).toBe("client_OJtz=[ =\\");
	expect(clientIdOfTokenRequest(request(basic("plain")))).toBe("plain");
	expect(clientIdOfTokenRequest(request({}, { client_id: "from the body" }))).toBe("from the body");
	expect(clientIdOfTokenRequest(request({}))).toBeNull();
});
