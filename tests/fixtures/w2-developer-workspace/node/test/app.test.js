import test from "node:test";
import assert from "node:assert/strict";
import { greeting } from "../src/app.js";

test("offline-installed local package is available in the workspace", () => {
  assert.equal(greeting(), "Tinlance Agent Workspace v1");
});
