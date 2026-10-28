import _ from "lodash";

const greet = _.template("Hello <%= name %>!");
console.log(greet({ name: "world" }));
