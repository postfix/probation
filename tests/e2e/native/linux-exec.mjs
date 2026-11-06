// How the Linux scenario starts publishing.mjs in the client container (S4). The policy
// service key is a secret: a command line is visible to every process of the machine and
// is logged by container engines, so the key goes in on stdin into a private file and only
// that file's path travels in the argv.
export function buildNativeRun({ key, policyUrl, npmId, pypiId, npmPort, hiddenName, keyFile = "/work/native.key" }) {
  return {
    keyInput: `${key}\n`,
    keyWriteArgv: ["sh", "-c", `umask 077; cat > ${keyFile}`],
    argv: ["env", `NATIVE_POLICY_URL=${policyUrl}`, `NATIVE_SERVICE_KEY_FILE=${keyFile}`, "NATIVE_POLICY_CA=/e2e/ca/ca.pem",
      `NATIVE_NPM_REGISTRY_ID=${npmId}`, `NATIVE_PYPI_REGISTRY_ID=${pypiId}`, `NATIVE_NPM_PORT=${npmPort}`, `NATIVE_HIDDEN_NAME=${hiddenName}`,
      "NATIVE_PLATFORM=linux-x64", "NATIVE_PROBATION_BINARY=/usr/local/bin/probation", "NATIVE_WORK=/work/native", "node", "/src/tests/e2e/native/publishing.mjs"],
  };
}
