// Matching command line arguments
// matches the arguments passed to the script and returns a map of the arguments
let cli_args = match_args(["signer", "build_flags"]);

// expect build flags to be a comma separated list of flags
// - no_rebuild: don't rebuild the contract
// - no_wasm_opt: don't optimize the wasm
let build_flags = cli_args.build_flags.split(",");

let base_args = #{
    signer_account: cli_args.signer,
    no_rebuild: build_flags.contains("no_rebuild"),
    no_wasm_opt: build_flags.contains("no_wasm_opt"),

    // contract name and label
    contract_name: "wbtc-controller",
    label: "wbtc-controller",
};

let owner_address = "osmo1cyyzpxplxdzkeea7kwsydadg87357qnahakaks"; // test1
let custodian_address = "osmo18s5lynnmx37hq4wlrw9gdn68sg2uxp5rgk26vv"; // test2
let merchant_addresses = [
    "osmo1qwexv7c6sm95lwhzn9027vyu2ccneaqad4w8ka", // test3
    "osmo14hcxlnwlqtq75ttaxf674vk6mafspg8xwgnn53" // test4
];

// deploy the contract
let wbtc_contract = wasm::deploy(merge(
    base_args,
    #{
        msg: #{
            owner: owner_address,
            subdenom: "wbtc"
        },
        funds: "10000000uosmo",
        admin: owner_address,
    },
));

print(">> set custodian: " + custodian_address);
wasm::execute(merge(
    base_args,
    #{
        msg: #{
            "set_custodian": #{ "address": custodian_address }
        }
    }
));

for merchant_address in merchant_addresses {
    print(">> add merchant: " + merchant_address);
    wasm::execute(merge(
        base_args,
        #{
            msg: #{
                "add_merchant": #{ "address": merchant_address }
            }
        }
    ));
}


// === validating contract state ===

// >> token denom
let token_denom = wasm::query(merge(
    base_args,
    #{
        msg: #{
            "get_token_denom": #{}
        }
    }
)).data.denom;

@assert(token_denom == "factory/" + wbtc_contract.contract_address + "/wbtc");

// >> custodian
let registered_custodian_address = wasm::query(merge(
    base_args,
    #{
        msg: #{
            "get_custodian": #{}
        }
    }
)).data.address;

@assert(registered_custodian_address == custodian_address);

// >> merchants

let registered_merchant_addresses = wasm::query(merge(
    base_args,
    #{
        msg: #{
            "list_merchants": #{}
        }
    }
)).data.merchants;

// sort the addresses to make sure they are in the same order
merchant_addresses.sort(); 
@assert(registered_merchant_addresses == merchant_addresses);