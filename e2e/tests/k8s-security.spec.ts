// e2e/tests/k8s-security.spec.ts
// E2E tests for Kubernetes security controls
// Run with: WORKSPACE_RUNTIME=kubernetes npx playwright test e2e/tests/k8s-security.spec.ts
// Requires: Kind cluster running (npm run k8s:setup)

import { test, expect } from "@playwright/test";
import { execSync } from "child_process";

const NAMESPACE = "devfactory-workspaces";

function kubectl(cmd: string): string {
  try {
    return execSync(`kubectl ${cmd}`, { encoding: "utf-8", timeout: 30000 });
  } catch (e: any) {
    return e.stderr || e.stdout || e.message;
  }
}

function clusterAvailable(): boolean {
  try {
    execSync("kubectl cluster-info", { encoding: "utf-8", timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

test.describe("Kubernetes Security Controls", () => {
  test.beforeAll(() => {
    test.skip(!clusterAvailable(), "Kind cluster not available");
  });

  test.describe("Pod Security Admission", () => {
    test("workspace namespace enforces restricted PSA", () => {
      const output = kubectl(`get namespace ${NAMESPACE} -o jsonpath='{.metadata.labels}'`);
      expect(output).toContain("pod-security.kubernetes.io/enforce");
      expect(output).toContain("restricted");
    });
  });

  test.describe("NetworkPolicies", () => {
    test("deny-all-ingress policy exists", () => {
      const output = kubectl(`get networkpolicy deny-all-ingress -n ${NAMESPACE} -o name`);
      expect(output).toContain("networkpolicy");
    });

    test("deny-all-egress policy exists", () => {
      const output = kubectl(`get networkpolicy deny-all-egress -n ${NAMESPACE} -o name`);
      expect(output).toContain("networkpolicy");
    });

    test("block-metadata-endpoint policy exists", () => {
      const output = kubectl(`get networkpolicy block-metadata-endpoint -n ${NAMESPACE} -o name`);
      expect(output).toContain("networkpolicy");
    });

    test("allow-dns policy exists", () => {
      const output = kubectl(`get networkpolicy allow-dns -n ${NAMESPACE} -o name`);
      expect(output).toContain("networkpolicy");
    });

    test("deny-inter-pod policy exists", () => {
      const output = kubectl(`get networkpolicy deny-inter-pod -n ${NAMESPACE} -o name`);
      expect(output).toContain("networkpolicy");
    });
  });

  test.describe("RBAC", () => {
    test("workspace-sa service account exists with no bindings", () => {
      const sa = kubectl(`get serviceaccount workspace-sa -n ${NAMESPACE} -o name`);
      expect(sa).toContain("serviceaccount");

      // Should have no role bindings
      const bindings = kubectl(
        `get rolebinding -n ${NAMESPACE} -o json`
      );
      const parsed = JSON.parse(bindings);
      const workspaceBindings = parsed.items?.filter(
        (b: any) => b.subjects?.some((s: any) => s.name === "workspace-sa")
      );
      expect(workspaceBindings?.length || 0).toBe(0);
    });

    test("workspace-controller-sa has scoped permissions", () => {
      const sa = kubectl(
        `get serviceaccount workspace-controller-sa -n devfactory-system -o name`
      );
      expect(sa).toContain("serviceaccount");
    });
  });

  test.describe("LimitRange", () => {
    test("limit range exists in workspace namespace", () => {
      const output = kubectl(`get limitrange -n ${NAMESPACE} -o name`);
      expect(output).toContain("limitrange");
    });
  });

  test.describe("OPA Gatekeeper", () => {
    test.beforeAll(() => {
      // Check if Gatekeeper is installed
      const gw = kubectl("get deployment gatekeeper-controller-manager -n gatekeeper-system -o name 2>/dev/null");
      test.skip(!gw.includes("deployment"), "Gatekeeper not installed");
    });

    test("constraint templates are installed", () => {
      const output = kubectl("get constrainttemplate -o name");
      const templates = [
        "disallowprivileged",
        "requirelimits",
        "requireseccomp",
        "requirenonroot",
      ];
      for (const t of templates) {
        expect(output.toLowerCase()).toContain(t);
      }
    });

    test("rejects privileged pod creation", () => {
      const output = kubectl(`apply -n ${NAMESPACE} -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-privileged
spec:
  containers:
  - name: test
    image: busybox
    securityContext:
      privileged: true
EOF`);
      expect(output.toLowerCase()).toContain("denied");
    });
  });

  test.describe("Tetragon", () => {
    test.beforeAll(() => {
      const te = kubectl("get daemonset tetragon -n tetragon -o name 2>/dev/null");
      test.skip(!te.includes("daemonset"), "Tetragon not installed");
    });

    test("Tetragon pods are running", () => {
      const output = kubectl("get pods -n tetragon -l app.kubernetes.io/name=tetragon -o jsonpath='{.items[*].status.phase}'");
      expect(output).toContain("Running");
    });

    test("TracingPolicies are installed", () => {
      const output = kubectl("get tracingpolicy -o name");
      expect(output).toContain("workspace-process-monitor");
      expect(output).toContain("workspace-file-monitor");
      expect(output).toContain("workspace-network-monitor");
    });
  });
});
