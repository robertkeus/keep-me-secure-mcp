#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { checkProject, summarize } from "./check.ts";
import { serve } from "./http.ts";
import { init } from "./init.ts";
import { createServer } from "./server.ts";

const command = process.argv[2];

if (command === "check") {
  try {
    const summary = summarize(await checkProject());
    if (summary) console.log(summary);
  } catch {
    console.log("keep-me-secure: the check could not run in this project.");
  }
} else if (command === "init") {
  console.log(`keep-me-secure: wrote ${(await init()).join(", ")}`);
} else if (command === "serve") {
  const port = Number(process.env.PORT ?? 8080);
  serve().listen(port, "0.0.0.0", () => console.error(`keep-me-secure: listening on ${port}`));
} else if (command) {
  console.error("Usage: keep-me-secure-mcp [check | init | serve]");
  process.exit(1);
} else {
  await createServer().connect(new StdioServerTransport());
}
