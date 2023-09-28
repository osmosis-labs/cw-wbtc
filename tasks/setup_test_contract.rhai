// Matching command line arguments
// matches the arguments passed to the script and returns a map of the arguments
let cli_args = match_args(["signer", "build_flags", "network"]);

// expect build flags to be a comma separated list of flags
// - no_rebuild: don't rebuild the contract
// - no_wasm_opt: don't optimize the wasm
let build_flags = cli_args.build_flags.split(",");

let base_args = #{
    signer_account: cli_args.signer,
    no_rebuild: build_flags.contains("no_rebuild"),
    no_wasm_opt: build_flags.contains("no_wasm_opt"),
    network: cli_args.network,

    // contract name and label
    contract_name: "wbtc-controller",
    label: "default",
};

let governor_address = "osmo1cyyzpxplxdzkeea7kwsydadg87357qnahakaks"; // test1
let member_manager_address = "osmo18s5lynnmx37hq4wlrw9gdn68sg2uxp5rgk26vv"; // test2
let custodian_address = "osmo1qwexv7c6sm95lwhzn9027vyu2ccneaqad4w8ka"; // test3
let merchant_addresses = [
    "osmo14hcxlnwlqtq75ttaxf674vk6mafspg8xwgnn53", // test4
    "osmo12rr534cer5c0vj53eq4y32lcwguyy7nndt0u2t" // test5
];

// deploy the contract
let wbtc_contract = wasm::deploy(merge(
    base_args,
    #{
        msg: #{
            governor: governor_address,
            subdenom: "wbtc"
        },
        admin: governor_address,
    },
));

print(">> set member manager: " + member_manager_address);
wasm::execute(merge(
    base_args,
    #{
        msg: #{
            "set_member_manager": #{ "address": member_manager_address }
        },
        signer_account: "test1" // governor
    }
));


print(">> set custodian: " + custodian_address);
wasm::execute(merge(
    base_args,
    #{
        msg: #{
            "set_custodian": #{ "address": custodian_address }
        },
        signer_account: "test2", // member manager
    }
));

for merchant_address in merchant_addresses {
    print(">> add merchant: " + merchant_address);
    wasm::execute(merge(
        base_args,
        #{
            msg: #{
                "add_merchant": #{ "address": merchant_address }
            },
            signer_account: "test2", // member manager
        }
    ));

    print(">> set mock custodian deposit address");
    wasm::execute(merge(
        base_args,
        #{
            msg: #{
                "set_custodian_deposit_address": #{
                    "merchant": merchant_address,
                    "deposit_address": "bc1" + merchant_address // mock btc address
                }
            },
            signer_account: "test3", // custodian
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
