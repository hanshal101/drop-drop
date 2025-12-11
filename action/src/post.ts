import * as core from '@actions/core';
import * as exec from '@actions/exec';

async function post() {
  try {
    const agentPid = core.getState('agentPid');
    if (agentPid) {
      core.info(`Killing agent with PID: ${agentPid}`);
      await exec.exec('kill', [agentPid]);
    }
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    }
  }
}

post();
