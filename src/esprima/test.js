const espree = require("espree");
const fs = require("fs");

const sourceCode = fs.readFileSync("../../jsx-test/example/react.jsx", {
  encoding: "utf-8",
});
console.log("sourceCode: ", sourceCode);
var root = espree.parse(sourceCode, {
  sourceType: "module",
  loc: true,
  range: true,
  comment: true,
  // tolerant: true,
  ecmaVersion: "latest",
  ecmaFeatures: {
    jsx: true,
  },
});
console.log("root: ", JSON.stringify(root));
fs.writeFileSync("./react.json", JSON.stringify(root));
