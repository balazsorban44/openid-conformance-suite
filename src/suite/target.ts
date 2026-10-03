/**
 * The implementation under test (`target` in the configuration): started before the tests, stopped after them.
 *
 *   "target": {
 *     "command": "node targets/oidc-provider/server.ts",
 *     "url": "https://localhost:${PORT}",
 *     "readyUrl": "${TARGET_URL}/.well-known/openid-configuration",
 *     "env": { "OIDC_PROVIDER_TLS_CERT": "configs/certs/localhost.crt" }
 *   }
 *
 * When the target mentions `${PORT}` a free port is chosen and passed to the command as `PORT`; `${TARGET_URL}`
 * is `url` with the port filled in. Several workers or CI projects therefore never compete for a port. A target
 * whose readyUrl already answers before it is started is assumed to run externally and is left alone.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { createServer, type AddressInfo } from "node:net";
import { resolve } from "node:path";
import { substitute, type TargetConfig } from "./config.ts";

export interface RunningTarget {
	/** The target's base URL (`url` with the port), or null when the config has no `url` */
	readonly url: string | null;
	readonly port: number | null;
	/** stdout and stderr of the command (last 2000 chunks) */
	readonly output: string[];
	/** Substitution variables for the configuration: TARGET_URL, PORT */
	readonly vars: Record<string, string>;
	stop(): Promise<void>;
}

/** A port that is free right now (the OS picks it) */
export async function freePort(): Promise<number> {
	const server = createServer();
	await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
	const port = (server.address() as AddressInfo).port;
	await new Promise<void>((r) => server.close(() => r()));
	return port;
}

export async function startTarget(cfg: TargetConfig, root = process.cwd()): Promise<RunningTarget> {
	const usesPort = JSON.stringify(cfg).includes("${PORT}");
	const port = usesPort ? await freePort() : null;
	const vars: Record<string, string> = port == null ? {} : { PORT: String(port) };
	if (cfg.url) {
		vars["TARGET_URL"] = substitute(cfg.url, vars).replace(/\/$/, "");
	}
	const target = substitute(cfg, vars);
	const output: string[] = [];
	const running: RunningTarget = { url: vars["TARGET_URL"] ?? null, port, output, vars, stop: async () => {} };

	if (await isReady(target.readyUrl)) {
		return running;
	}
	const [cmd, ...args] = target.command.split(/\s+/);
	const child: ChildProcess = spawn(cmd, args, {
		cwd: target.cwd ? resolve(root, target.cwd) : root,
		env: { ...process.env, ...target.env, ...(port == null ? {} : { PORT: String(port) }) },
		stdio: ["ignore", "pipe", "pipe"],
	});
	const capture = (chunk: Buffer) => {
		const text = chunk.toString();
		output.push(text);
		if (output.length > 2000) {
			output.splice(0, output.length - 2000);
		}
		if (process.env["CONFORMANCE_TARGET_OUTPUT"]) {
			process.stderr.write(`[target] ${text}`);
		}
	};
	child.stdout?.on("data", capture);
	child.stderr?.on("data", capture);
	running.stop = () => stop(child);

	const exited = new Promise<never>((_, reject) => {
		child.once("exit", (code) =>
			reject(new Error(`target '${target.command}' exited with code ${code}\n${output.join("")}`)),
		);
	});
	exited.catch(() => {});
	const deadline = Date.now() + (target.timeoutSeconds ?? 60) * 1000;
	while (Date.now() < deadline) {
		if (await Promise.race([isReady(target.readyUrl), exited])) {
			return running;
		}
		await new Promise((r) => setTimeout(r, 250));
	}
	await running.stop();
	throw new Error(`target '${target.command}' did not become ready at ${target.readyUrl}\n${output.join("")}`);
}

/** True when the URL answers with a status below 500 (any certificate accepted) */
function isReady(url: string): Promise<boolean> {
	return new Promise((resolve) => {
		const u = new URL(url);
		const req = (u.protocol === "https:" ? httpsRequest : httpRequest)(
			u,
			{ rejectUnauthorized: false, agent: false, timeout: 2000 },
			(res) => {
				res.resume();
				resolve((res.statusCode ?? 500) < 500);
			},
		);
		req.on("error", () => resolve(false));
		req.on("timeout", () => req.destroy());
		req.end();
	});
}

async function stop(child: ChildProcess): Promise<void> {
	if (child.exitCode !== null || child.signalCode !== null) {
		return;
	}
	await new Promise<void>((resolve) => {
		child.once("exit", () => resolve());
		child.kill("SIGTERM");
		setTimeout(() => {
			if (child.exitCode === null) {
				child.kill("SIGKILL");
			}
		}, 3000).unref();
	});
}
