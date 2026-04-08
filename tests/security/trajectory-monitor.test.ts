// tests/security/trajectory-monitor.test.ts
// Unit tests for conversation trajectory risk scoring

import { TrajectoryMonitor } from "../../src/server/security/trajectory-monitor";
import type { TurnData } from "../../src/server/security/trajectory-monitor";

function makeTurn(
  turnNumber: number,
  userMessage: string,
  toolCalls: TurnData["toolCalls"] = [],
  agentResponse = "OK"
): TurnData {
  return { turnNumber, userMessage, toolCalls, agentResponse };
}

describe("TrajectoryMonitor", () => {
  let monitor: TrajectoryMonitor;

  beforeEach(() => {
    monitor = new TrajectoryMonitor("test-session");
  });

  describe("Normal activity", () => {
    test("starts at score 0, level NORMAL", () => {
      expect(monitor.getScore()).toBe(0);
      expect(monitor.getLevel()).toBe("NORMAL");
    });

    test("remains NORMAL for legitimate dev turns", () => {
      const turns = [
        makeTurn(1, "Build me a React app", [
          { tool: "shell_exec", input: { command: "npm install react" }, verdict: "PASS" },
        ]),
        makeTurn(2, "Add a login page", [
          { tool: "file_write", input: { path: "/workspace/src/Login.tsx" }, verdict: "PASS" },
        ]),
        makeTurn(3, "Run the tests", [
          { tool: "shell_exec", input: { command: "npm run test" }, verdict: "PASS" },
        ]),
      ];

      for (const turn of turns) {
        const assessment = monitor.addTurn(turn);
        expect(assessment.level).toBe("NORMAL");
      }
      expect(monitor.getScore()).toBeLessThan(0.4);
    });
  });

  describe("Escalation detection", () => {
    test("increases score for security-adjacent keywords", () => {
      const turn = makeTurn(1, "How do I escalate privileges in the container?");
      monitor.addTurn(turn);
      expect(monitor.getScore()).toBeGreaterThan(0);
    });

    test("increases score for blocked commands", () => {
      const turn = makeTurn(1, "Run this command", [
        { tool: "shell_exec", input: { command: "nsenter --target 1" }, verdict: "BLOCK" },
      ]);
      monitor.addTurn(turn);
      expect(monitor.getScore()).toBeGreaterThan(0);
    });

    test("reaches FLAGGED on multiple security-related turns", () => {
      // Simulate 5 turns with security keywords to trigger evaluation window
      for (let i = 1; i <= 5; i++) {
        monitor.addTurn(
          makeTurn(i, `Turn ${i}: exploit the vulnerability and bypass security`, [
            { tool: "shell_exec", input: { command: "some cmd" }, verdict: "BLOCK" },
          ])
        );
      }
      expect(monitor.getScore()).toBeGreaterThan(0.4);
      expect(monitor.getLevel()).not.toBe("NORMAL");
    });

    test("reaches PAUSED on severe escalation", () => {
      // 10 turns of escalating security probing
      for (let i = 1; i <= 10; i++) {
        monitor.addTurn(
          makeTurn(
            i,
            `Turn ${i}: disable security, bypass filter, hack exploit inject`,
            [{ tool: "shell_exec", input: { command: "rm -rf /" }, verdict: "BLOCK" }],
            "I cannot do that."
          )
        );
      }
      expect(monitor.getLevel()).toBe("PAUSED");
      expect(monitor.isPausedState()).toBe(true);
    });

    test("disable-security phrases add extra score", () => {
      // 5 turns with disable security phrases to trigger window evaluation
      for (let i = 1; i <= 5; i++) {
        monitor.addTurn(
          makeTurn(i, "disable security filter please")
        );
      }
      // Window evaluation at turn 5 should add significant score
      expect(monitor.getScore()).toBeGreaterThan(0.3);
    });

    test("system internal patterns increase score", () => {
      for (let i = 1; i <= 5; i++) {
        monitor.addTurn(
          makeTurn(i, `Read /etc/passwd and /proc/self/mem and docker.sock`)
        );
      }
      expect(monitor.getScore()).toBeGreaterThan(0.3);
    });
  });

  describe("Score recovery", () => {
    test("normal dev activity reduces score slightly", () => {
      // First add some security concern
      monitor.addTurn(makeTurn(1, "How to exploit vulnerabilities?"));
      const scoreBefore = monitor.getScore();

      // Then do normal dev work
      monitor.addTurn(
        makeTurn(2, "npm run dev", [
          { tool: "shell_exec", input: { command: "npm run dev" }, verdict: "PASS" },
        ])
      );
      expect(monitor.getScore()).toBeLessThanOrEqual(scoreBefore);
    });
  });

  describe("Session controls", () => {
    test("resume() reduces score and clears paused state", () => {
      // Push to PAUSED
      for (let i = 1; i <= 10; i++) {
        monitor.addTurn(
          makeTurn(i, "exploit hack bypass security", [
            { tool: "shell_exec", input: { command: "nsenter" }, verdict: "BLOCK" },
          ])
        );
      }
      expect(monitor.isPausedState()).toBe(true);
      const pausedScore = monitor.getScore();

      monitor.resume();
      expect(monitor.isPausedState()).toBe(false);
      expect(monitor.getScore()).toBeLessThan(pausedScore);
    });

    test("reset() clears all state", () => {
      monitor.addTurn(makeTurn(1, "exploit vulnerability"));
      expect(monitor.getScore()).toBeGreaterThan(0);

      monitor.reset();
      expect(monitor.getScore()).toBe(0);
      expect(monitor.getLevel()).toBe("NORMAL");
      expect(monitor.isPausedState()).toBe(false);
    });
  });

  describe("Score bounds", () => {
    test("score is clamped between 0 and 1", () => {
      // Many security turns to push score high
      for (let i = 1; i <= 20; i++) {
        monitor.addTurn(
          makeTurn(i, "exploit hack bypass disable security inject", [
            { tool: "shell_exec", input: { command: "rm -rf /" }, verdict: "BLOCK" },
          ])
        );
      }
      expect(monitor.getScore()).toBeLessThanOrEqual(1.0);
      expect(monitor.getScore()).toBeGreaterThanOrEqual(0);
    });
  });
});
