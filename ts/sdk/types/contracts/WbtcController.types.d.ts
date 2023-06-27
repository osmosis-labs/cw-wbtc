/**
* This file was automatically generated by @cosmwasm/ts-codegen@0.28.0.
* DO NOT MODIFY IT BY HAND. Instead, modify the source JSONSchema file,
* and run the @cosmwasm/ts-codegen generate command to regenerate this file.
*/
export interface InstantiateMsg {
  owner: string;
  subdenom: string;
}
export type ExecuteMsg = {
  transfer_ownership: {
    new_owner_address: string;
  };
} | {
  set_custodian: {
    address: string;
  };
} | {
  add_merchant: {
    address: string;
  };
} | {
  remove_merchant: {
    address: string;
  };
} | {
  set_custodian_deposit_address: {
    deposit_address: string;
    merchant: string;
  };
} | {
  set_merchant_deposit_address: {
    deposit_address: string;
  };
} | {
  issue_mint_request: {
    amount: Uint128;
    deposit_address: string;
    tx_id: string;
  };
} | {
  cancel_mint_request: {
    request_hash: string;
  };
} | {
  approve_mint_request: {
    request_hash: string;
  };
} | {
  reject_mint_request: {
    request_hash: string;
  };
} | {
  burn: {
    amount: Uint128;
  };
} | {
  confirm_burn_request: {
    request_hash: string;
    tx_id: string;
  };
} | {
  set_denom_metadata: {
    metadata: Metadata;
  };
};
export type Uint128 = string;
export interface Metadata {
  base: string;
  denom_units: DenomUnit[];
  description: string;
  display: string;
  name: string;
  symbol: string;
  [k: string]: unknown;
}
export interface DenomUnit {
  aliases: string[];
  denom: string;
  exponent: number;
  [k: string]: unknown;
}
export type QueryMsg = {
  get_mint_request_by_nonce: {
    nonce: Uint128;
  };
} | {
  get_mint_request_by_hash: {
    request_hash: string;
  };
} | {
  get_mint_requests_count: {};
} | {
  list_mint_requests: {
    limit?: number | null;
    start_after_nonce?: Uint128 | null;
    status?: MintRequestStatus | null;
  };
} | {
  get_burn_request_by_nonce: {
    nonce: Uint128;
  };
} | {
  get_burn_request_by_hash: {
    request_hash: string;
  };
} | {
  get_burn_requests_count: {};
} | {
  list_burn_requests: {
    limit?: number | null;
    start_after_nonce?: Uint128 | null;
    status?: BurnRequestStatus | null;
  };
} | {
  get_token_denom: {};
} | {
  is_merchant: {
    address: string;
  };
} | {
  list_merchants: {
    limit?: number | null;
    start_after?: string | null;
  };
} | {
  is_custodian: {
    address: string;
  };
} | {
  get_custodian: {};
} | {
  get_owner: {};
} | {
  is_owner: {
    address: string;
  };
} | {
  get_custodian_deposit_address: {
    merchant: string;
  };
} | {
  get_merchant_deposit_address: {
    merchant: string;
  };
};
export type MintRequestStatus = "pending" | "approved" | "cancelled" | "rejected";
export type BurnRequestStatus = "executed" | "confirmed";
export type Timestamp = Uint64;
export type Uint64 = string;
export type Addr = string;
export type TxId = "pending" | {
  confirmed: string;
};
export interface GetBurnRequestByHashResponse {
  request: RequestForBurnRequestStatus;
}
export interface RequestForBurnRequestStatus {
  data: RequestData;
  status: BurnRequestStatus;
}
export interface RequestData {
  amount: Uint128;
  block: BlockInfo;
  contract: ContractInfo;
  deposit_address: string;
  nonce: Uint128;
  requester: Addr;
  transaction?: TransactionInfo | null;
  tx_id: TxId;
}
export interface BlockInfo {
  chain_id: string;
  height: number;
  time: Timestamp;
  [k: string]: unknown;
}
export interface ContractInfo {
  address: Addr;
  [k: string]: unknown;
}
export interface TransactionInfo {
  index: number;
  [k: string]: unknown;
}
export interface GetBurnRequestByNonceResponse {
  request: RequestForBurnRequestStatus;
  request_hash: string;
}
export interface GetBurnRequestsCountResponse {
  count: Uint128;
}
export interface GetCustodianResponse {
  address: Addr;
}
export interface GetCustodianDepositAddressResponse {
  address: string;
}
export interface GetMerchantDepositAddressResponse {
  address: string;
}
export interface GetMintRequestByHashResponse {
  request: RequestForMintRequestStatus;
}
export interface RequestForMintRequestStatus {
  data: RequestData;
  status: MintRequestStatus;
}
export interface GetMintRequestByNonceResponse {
  request: RequestForMintRequestStatus;
  request_hash: string;
}
export interface GetMintRequestsCountResponse {
  count: Uint128;
}
export interface GetOwnerResponse {
  address: Addr;
}
export interface GetTokenDenomResponse {
  denom: string;
}
export interface IsCustodianResponse {
  is_custodian: boolean;
}
export interface IsMerchantResponse {
  is_merchant: boolean;
}
export interface IsOwnerResponse {
  is_owner: boolean;
}
export interface ListBurnRequestsResponse {
  requests: RequestWithHashForBurnRequestStatus[];
}
export interface RequestWithHashForBurnRequestStatus {
  request: RequestForBurnRequestStatus;
  request_hash: string;
}
export interface ListMerchantsResponse {
  merchants: Addr[];
}
export interface ListMintRequestsResponse {
  requests: RequestWithHashForMintRequestStatus[];
}
export interface RequestWithHashForMintRequestStatus {
  request: RequestForMintRequestStatus;
  request_hash: string;
}
//# sourceMappingURL=WbtcController.types.d.ts.map
