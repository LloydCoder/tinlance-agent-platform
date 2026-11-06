import test from "node:test";
import assert from "node:assert/strict";
import { greeting } from "../src/app.js";

test("greeting is editable and testable", () => {
  assert.equal(greeting(), "Tinlance Agent Workspace");
});
