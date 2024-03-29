const codegen = require("@cosmwasm/ts-codegen").default;
const path = require("path");
const fs = require("fs");

const pkgRoot = path.join(__dirname, "..");
const contractsDir = path.join(pkgRoot, "..", "..", "contracts");

const contracts = fs
  .readdirSync(contractsDir, { withFileTypes: true })
  .filter((c) => c.isDirectory())
  .map((c) => ({
    name: c.name,
    dir: path.join(contractsDir, c.name, "schema"),
  }));

const outPath = path.join(pkgRoot, "src", "contracts");
fs.rmSync(outPath, { recursive: true, force: true });

// patch missing description
contracts.forEach((contract) => {
  const mainSchemaFile = path.join(contract.dir, contract.name + ".json")
  const schema = JSON.parse(fs.readFileSync(mainSchemaFile));

  fs.writeFileSync(mainSchemaFile, JSON.stringify(schema, null, 2));
})

codegen({
  contracts,
  outPath,
  options: {
    bundle: {
      bundleFile: "index.ts",
      scope: "contracts",
    },
  },
}).then(() => {
  console.log("✨ Typescript code is generated successfully!");
});
