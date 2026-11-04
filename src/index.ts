#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { checkProject, summarize } from "./check.ts";
import { init } from "./init.ts";
import { createServer } from "./server.ts";

const command = process.argv[2];

if (command === "check") {
  console.log(summarize(await checkProject()));
} else if (command === "init") {
  console.log(`keep-me-secure: wrote ${(await init()).join(", ")}`);
} else if (command) {
  console.error("Usage: keep-me-secure-mcp [check | init]");
  process.exit(1);
} else {
  await createServer().connect(new StdioServerTransport());
}
