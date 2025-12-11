import * as core from "@actions/core";
import * as tc from "@actions/tool-cache";
import * as exec from "@actions/exec";
import * as path from "path";
import * as fs from "fs";
import { spawn } from "child_process";

async function run() {
  try {
    const firewallMode = core.getInput("firewall-mode");
    const tetragonAddress = core.getInput("tetragon-address");
    const agentUrl = core.getInput("agent-url");
    const installTetragon = core.getBooleanInput("install-tetragon");
    const nfqueueNum = core.getInput("nfqueue-num");

    if (installTetragon) {
      core.info("Installing Tetragon");
      const installScript = path.join(
        __dirname,
        "../scripts/install_tetragon.sh",
      );
      await exec.exec("bash", [installScript]);
    }

    core.info(`Firewall mode: ${firewallMode}`);
    core.info(`Tetragon address: ${tetragonAddress}`);
    core.info(`Agent URL: ${agentUrl}`);
    core.info(`NFQueue number: ${nfqueueNum}`);

    const agentPath = await tc.downloadTool(agentUrl);
    const agentDirectory = path.dirname(agentPath);
    const agentBinary = path.join(agentDirectory, "agent");
    fs.renameSync(agentPath, agentBinary);
    fs.chmodSync(agentBinary, "755");

    const args = [
      `--firewall-mode=${firewallMode}`,
      `--tetragon-address=${tetragonAddress}`,
      `--nfqueue-num=${nfqueueNum}`,
    ];

    const child = spawn(agentBinary, args, {
      detached: true,
      stdio: "ignore",
    });

    child.unref();

    core.saveState("agentPid", child.pid);
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    }
  }
}

run();
