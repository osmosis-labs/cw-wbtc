/**
* This file was automatically generated by @cosmwasm/ts-codegen@0.28.0.
* DO NOT MODIFY IT BY HAND. Instead, modify the source JSONSchema file,
* and run the @cosmwasm/ts-codegen generate command to regenerate this file.
*/

import { CosmWasmClient, SigningCosmWasmClient, ExecuteResult } from "@cosmjs/cosmwasm-stargate";
import { Coin, StdFee } from "@cosmjs/amino";
import { InstantiateMsg, ExecuteMsg, Uint128, Metadata, DenomUnit, QueryMsg, MintRequestStatus, BurnRequestStatus, Timestamp, Uint64, Addr, TxId, GetBurnRequestByHashResponse, RequestForBurnRequestStatus, RequestData, BlockInfo, ContractInfo, TransactionInfo, GetBurnRequestByNonceResponse, GetBurnRequestsCountResponse, GetCustodianResponse, GetCustodianDepositAddressResponse, GetMerchantDepositAddressResponse, GetMintRequestByHashResponse, RequestForMintRequestStatus, GetMintRequestByNonceResponse, GetMintRequestsCountResponse, GetOwnerResponse, GetTokenDenomResponse, IsCustodianResponse, IsMerchantResponse, IsOwnerResponse, ListBurnRequestsResponse, RequestWithHashForBurnRequestStatus, ListMerchantsResponse, ListMintRequestsResponse, RequestWithHashForMintRequestStatus } from "./WbtcController.types";
export interface WbtcControllerReadOnlyInterface {
  contractAddress: string;
  getMintRequestByNonce: ({
    nonce
  }: {
    nonce: Uint128;
  }) => Promise<GetMintRequestByNonceResponse>;
  getMintRequestByHash: ({
    requestHash
  }: {
    requestHash: string;
  }) => Promise<GetMintRequestByHashResponse>;
  getMintRequestsCount: () => Promise<GetMintRequestsCountResponse>;
  listMintRequests: ({
    limit,
    startAfterNonce,
    status
  }: {
    limit?: number;
    startAfterNonce?: Uint128;
    status?: MintRequestStatus;
  }) => Promise<ListMintRequestsResponse>;
  getBurnRequestByNonce: ({
    nonce
  }: {
    nonce: Uint128;
  }) => Promise<GetBurnRequestByNonceResponse>;
  getBurnRequestByHash: ({
    requestHash
  }: {
    requestHash: string;
  }) => Promise<GetBurnRequestByHashResponse>;
  getBurnRequestsCount: () => Promise<GetBurnRequestsCountResponse>;
  listBurnRequests: ({
    limit,
    startAfterNonce,
    status
  }: {
    limit?: number;
    startAfterNonce?: Uint128;
    status?: BurnRequestStatus;
  }) => Promise<ListBurnRequestsResponse>;
  getTokenDenom: () => Promise<GetTokenDenomResponse>;
  isMerchant: ({
    address
  }: {
    address: string;
  }) => Promise<IsMerchantResponse>;
  listMerchants: ({
    limit,
    startAfter
  }: {
    limit?: number;
    startAfter?: string;
  }) => Promise<ListMerchantsResponse>;
  isCustodian: ({
    address
  }: {
    address: string;
  }) => Promise<IsCustodianResponse>;
  getCustodian: () => Promise<GetCustodianResponse>;
  getOwner: () => Promise<GetOwnerResponse>;
  isOwner: ({
    address
  }: {
    address: string;
  }) => Promise<IsOwnerResponse>;
  getCustodianDepositAddress: ({
    merchant
  }: {
    merchant: string;
  }) => Promise<GetCustodianDepositAddressResponse>;
  getMerchantDepositAddress: ({
    merchant
  }: {
    merchant: string;
  }) => Promise<GetMerchantDepositAddressResponse>;
}
export class WbtcControllerQueryClient implements WbtcControllerReadOnlyInterface {
  client: CosmWasmClient;
  contractAddress: string;

  constructor(client: CosmWasmClient, contractAddress: string) {
    this.client = client;
    this.contractAddress = contractAddress;
    this.getMintRequestByNonce = this.getMintRequestByNonce.bind(this);
    this.getMintRequestByHash = this.getMintRequestByHash.bind(this);
    this.getMintRequestsCount = this.getMintRequestsCount.bind(this);
    this.listMintRequests = this.listMintRequests.bind(this);
    this.getBurnRequestByNonce = this.getBurnRequestByNonce.bind(this);
    this.getBurnRequestByHash = this.getBurnRequestByHash.bind(this);
    this.getBurnRequestsCount = this.getBurnRequestsCount.bind(this);
    this.listBurnRequests = this.listBurnRequests.bind(this);
    this.getTokenDenom = this.getTokenDenom.bind(this);
    this.isMerchant = this.isMerchant.bind(this);
    this.listMerchants = this.listMerchants.bind(this);
    this.isCustodian = this.isCustodian.bind(this);
    this.getCustodian = this.getCustodian.bind(this);
    this.getOwner = this.getOwner.bind(this);
    this.isOwner = this.isOwner.bind(this);
    this.getCustodianDepositAddress = this.getCustodianDepositAddress.bind(this);
    this.getMerchantDepositAddress = this.getMerchantDepositAddress.bind(this);
  }

  getMintRequestByNonce = async ({
    nonce
  }: {
    nonce: Uint128;
  }): Promise<GetMintRequestByNonceResponse> => {
    return this.client.queryContractSmart(this.contractAddress, {
      get_mint_request_by_nonce: {
        nonce
      }
    });
  };
  getMintRequestByHash = async ({
    requestHash
  }: {
    requestHash: string;
  }): Promise<GetMintRequestByHashResponse> => {
    return this.client.queryContractSmart(this.contractAddress, {
      get_mint_request_by_hash: {
        request_hash: requestHash
      }
    });
  };
  getMintRequestsCount = async (): Promise<GetMintRequestsCountResponse> => {
    return this.client.queryContractSmart(this.contractAddress, {
      get_mint_requests_count: {}
    });
  };
  listMintRequests = async ({
    limit,
    startAfterNonce,
    status
  }: {
    limit?: number;
    startAfterNonce?: Uint128;
    status?: MintRequestStatus;
  }): Promise<ListMintRequestsResponse> => {
    return this.client.queryContractSmart(this.contractAddress, {
      list_mint_requests: {
        limit,
        start_after_nonce: startAfterNonce,
        status
      }
    });
  };
  getBurnRequestByNonce = async ({
    nonce
  }: {
    nonce: Uint128;
  }): Promise<GetBurnRequestByNonceResponse> => {
    return this.client.queryContractSmart(this.contractAddress, {
      get_burn_request_by_nonce: {
        nonce
      }
    });
  };
  getBurnRequestByHash = async ({
    requestHash
  }: {
    requestHash: string;
  }): Promise<GetBurnRequestByHashResponse> => {
    return this.client.queryContractSmart(this.contractAddress, {
      get_burn_request_by_hash: {
        request_hash: requestHash
      }
    });
  };
  getBurnRequestsCount = async (): Promise<GetBurnRequestsCountResponse> => {
    return this.client.queryContractSmart(this.contractAddress, {
      get_burn_requests_count: {}
    });
  };
  listBurnRequests = async ({
    limit,
    startAfterNonce,
    status
  }: {
    limit?: number;
    startAfterNonce?: Uint128;
    status?: BurnRequestStatus;
  }): Promise<ListBurnRequestsResponse> => {
    return this.client.queryContractSmart(this.contractAddress, {
      list_burn_requests: {
        limit,
        start_after_nonce: startAfterNonce,
        status
      }
    });
  };
  getTokenDenom = async (): Promise<GetTokenDenomResponse> => {
    return this.client.queryContractSmart(this.contractAddress, {
      get_token_denom: {}
    });
  };
  isMerchant = async ({
    address
  }: {
    address: string;
  }): Promise<IsMerchantResponse> => {
    return this.client.queryContractSmart(this.contractAddress, {
      is_merchant: {
        address
      }
    });
  };
  listMerchants = async ({
    limit,
    startAfter
  }: {
    limit?: number;
    startAfter?: string;
  }): Promise<ListMerchantsResponse> => {
    return this.client.queryContractSmart(this.contractAddress, {
      list_merchants: {
        limit,
        start_after: startAfter
      }
    });
  };
  isCustodian = async ({
    address
  }: {
    address: string;
  }): Promise<IsCustodianResponse> => {
    return this.client.queryContractSmart(this.contractAddress, {
      is_custodian: {
        address
      }
    });
  };
  getCustodian = async (): Promise<GetCustodianResponse> => {
    return this.client.queryContractSmart(this.contractAddress, {
      get_custodian: {}
    });
  };
  getOwner = async (): Promise<GetOwnerResponse> => {
    return this.client.queryContractSmart(this.contractAddress, {
      get_owner: {}
    });
  };
  isOwner = async ({
    address
  }: {
    address: string;
  }): Promise<IsOwnerResponse> => {
    return this.client.queryContractSmart(this.contractAddress, {
      is_owner: {
        address
      }
    });
  };
  getCustodianDepositAddress = async ({
    merchant
  }: {
    merchant: string;
  }): Promise<GetCustodianDepositAddressResponse> => {
    return this.client.queryContractSmart(this.contractAddress, {
      get_custodian_deposit_address: {
        merchant
      }
    });
  };
  getMerchantDepositAddress = async ({
    merchant
  }: {
    merchant: string;
  }): Promise<GetMerchantDepositAddressResponse> => {
    return this.client.queryContractSmart(this.contractAddress, {
      get_merchant_deposit_address: {
        merchant
      }
    });
  };
}
export interface WbtcControllerInterface extends WbtcControllerReadOnlyInterface {
  contractAddress: string;
  sender: string;
  transferOwnership: ({
    newOwnerAddress
  }: {
    newOwnerAddress: string;
  }, fee?: number | StdFee | "auto", memo?: string, funds?: Coin[]) => Promise<ExecuteResult>;
  setCustodian: ({
    address
  }: {
    address: string;
  }, fee?: number | StdFee | "auto", memo?: string, funds?: Coin[]) => Promise<ExecuteResult>;
  addMerchant: ({
    address
  }: {
    address: string;
  }, fee?: number | StdFee | "auto", memo?: string, funds?: Coin[]) => Promise<ExecuteResult>;
  removeMerchant: ({
    address
  }: {
    address: string;
  }, fee?: number | StdFee | "auto", memo?: string, funds?: Coin[]) => Promise<ExecuteResult>;
  setCustodianDepositAddress: ({
    depositAddress,
    merchant
  }: {
    depositAddress: string;
    merchant: string;
  }, fee?: number | StdFee | "auto", memo?: string, funds?: Coin[]) => Promise<ExecuteResult>;
  setMerchantDepositAddress: ({
    depositAddress
  }: {
    depositAddress: string;
  }, fee?: number | StdFee | "auto", memo?: string, funds?: Coin[]) => Promise<ExecuteResult>;
  issueMintRequest: ({
    amount,
    depositAddress,
    txId
  }: {
    amount: Uint128;
    depositAddress: string;
    txId: string;
  }, fee?: number | StdFee | "auto", memo?: string, funds?: Coin[]) => Promise<ExecuteResult>;
  cancelMintRequest: ({
    requestHash
  }: {
    requestHash: string;
  }, fee?: number | StdFee | "auto", memo?: string, funds?: Coin[]) => Promise<ExecuteResult>;
  approveMintRequest: ({
    requestHash
  }: {
    requestHash: string;
  }, fee?: number | StdFee | "auto", memo?: string, funds?: Coin[]) => Promise<ExecuteResult>;
  rejectMintRequest: ({
    requestHash
  }: {
    requestHash: string;
  }, fee?: number | StdFee | "auto", memo?: string, funds?: Coin[]) => Promise<ExecuteResult>;
  burn: ({
    amount
  }: {
    amount: Uint128;
  }, fee?: number | StdFee | "auto", memo?: string, funds?: Coin[]) => Promise<ExecuteResult>;
  confirmBurnRequest: ({
    requestHash,
    txId
  }: {
    requestHash: string;
    txId: string;
  }, fee?: number | StdFee | "auto", memo?: string, funds?: Coin[]) => Promise<ExecuteResult>;
  setDenomMetadata: ({
    metadata
  }: {
    metadata: Metadata;
  }, fee?: number | StdFee | "auto", memo?: string, funds?: Coin[]) => Promise<ExecuteResult>;
}
export class WbtcControllerClient extends WbtcControllerQueryClient implements WbtcControllerInterface {
  client: SigningCosmWasmClient;
  sender: string;
  contractAddress: string;

  constructor(client: SigningCosmWasmClient, sender: string, contractAddress: string) {
    super(client, contractAddress);
    this.client = client;
    this.sender = sender;
    this.contractAddress = contractAddress;
    this.transferOwnership = this.transferOwnership.bind(this);
    this.setCustodian = this.setCustodian.bind(this);
    this.addMerchant = this.addMerchant.bind(this);
    this.removeMerchant = this.removeMerchant.bind(this);
    this.setCustodianDepositAddress = this.setCustodianDepositAddress.bind(this);
    this.setMerchantDepositAddress = this.setMerchantDepositAddress.bind(this);
    this.issueMintRequest = this.issueMintRequest.bind(this);
    this.cancelMintRequest = this.cancelMintRequest.bind(this);
    this.approveMintRequest = this.approveMintRequest.bind(this);
    this.rejectMintRequest = this.rejectMintRequest.bind(this);
    this.burn = this.burn.bind(this);
    this.confirmBurnRequest = this.confirmBurnRequest.bind(this);
    this.setDenomMetadata = this.setDenomMetadata.bind(this);
  }

  transferOwnership = async ({
    newOwnerAddress
  }: {
    newOwnerAddress: string;
  }, fee: number | StdFee | "auto" = "auto", memo?: string, funds?: Coin[]): Promise<ExecuteResult> => {
    return await this.client.execute(this.sender, this.contractAddress, {
      transfer_ownership: {
        new_owner_address: newOwnerAddress
      }
    }, fee, memo, funds);
  };
  setCustodian = async ({
    address
  }: {
    address: string;
  }, fee: number | StdFee | "auto" = "auto", memo?: string, funds?: Coin[]): Promise<ExecuteResult> => {
    return await this.client.execute(this.sender, this.contractAddress, {
      set_custodian: {
        address
      }
    }, fee, memo, funds);
  };
  addMerchant = async ({
    address
  }: {
    address: string;
  }, fee: number | StdFee | "auto" = "auto", memo?: string, funds?: Coin[]): Promise<ExecuteResult> => {
    return await this.client.execute(this.sender, this.contractAddress, {
      add_merchant: {
        address
      }
    }, fee, memo, funds);
  };
  removeMerchant = async ({
    address
  }: {
    address: string;
  }, fee: number | StdFee | "auto" = "auto", memo?: string, funds?: Coin[]): Promise<ExecuteResult> => {
    return await this.client.execute(this.sender, this.contractAddress, {
      remove_merchant: {
        address
      }
    }, fee, memo, funds);
  };
  setCustodianDepositAddress = async ({
    depositAddress,
    merchant
  }: {
    depositAddress: string;
    merchant: string;
  }, fee: number | StdFee | "auto" = "auto", memo?: string, funds?: Coin[]): Promise<ExecuteResult> => {
    return await this.client.execute(this.sender, this.contractAddress, {
      set_custodian_deposit_address: {
        deposit_address: depositAddress,
        merchant
      }
    }, fee, memo, funds);
  };
  setMerchantDepositAddress = async ({
    depositAddress
  }: {
    depositAddress: string;
  }, fee: number | StdFee | "auto" = "auto", memo?: string, funds?: Coin[]): Promise<ExecuteResult> => {
    return await this.client.execute(this.sender, this.contractAddress, {
      set_merchant_deposit_address: {
        deposit_address: depositAddress
      }
    }, fee, memo, funds);
  };
  issueMintRequest = async ({
    amount,
    depositAddress,
    txId
  }: {
    amount: Uint128;
    depositAddress: string;
    txId: string;
  }, fee: number | StdFee | "auto" = "auto", memo?: string, funds?: Coin[]): Promise<ExecuteResult> => {
    return await this.client.execute(this.sender, this.contractAddress, {
      issue_mint_request: {
        amount,
        deposit_address: depositAddress,
        tx_id: txId
      }
    }, fee, memo, funds);
  };
  cancelMintRequest = async ({
    requestHash
  }: {
    requestHash: string;
  }, fee: number | StdFee | "auto" = "auto", memo?: string, funds?: Coin[]): Promise<ExecuteResult> => {
    return await this.client.execute(this.sender, this.contractAddress, {
      cancel_mint_request: {
        request_hash: requestHash
      }
    }, fee, memo, funds);
  };
  approveMintRequest = async ({
    requestHash
  }: {
    requestHash: string;
  }, fee: number | StdFee | "auto" = "auto", memo?: string, funds?: Coin[]): Promise<ExecuteResult> => {
    return await this.client.execute(this.sender, this.contractAddress, {
      approve_mint_request: {
        request_hash: requestHash
      }
    }, fee, memo, funds);
  };
  rejectMintRequest = async ({
    requestHash
  }: {
    requestHash: string;
  }, fee: number | StdFee | "auto" = "auto", memo?: string, funds?: Coin[]): Promise<ExecuteResult> => {
    return await this.client.execute(this.sender, this.contractAddress, {
      reject_mint_request: {
        request_hash: requestHash
      }
    }, fee, memo, funds);
  };
  burn = async ({
    amount
  }: {
    amount: Uint128;
  }, fee: number | StdFee | "auto" = "auto", memo?: string, funds?: Coin[]): Promise<ExecuteResult> => {
    return await this.client.execute(this.sender, this.contractAddress, {
      burn: {
        amount
      }
    }, fee, memo, funds);
  };
  confirmBurnRequest = async ({
    requestHash,
    txId
  }: {
    requestHash: string;
    txId: string;
  }, fee: number | StdFee | "auto" = "auto", memo?: string, funds?: Coin[]): Promise<ExecuteResult> => {
    return await this.client.execute(this.sender, this.contractAddress, {
      confirm_burn_request: {
        request_hash: requestHash,
        tx_id: txId
      }
    }, fee, memo, funds);
  };
  setDenomMetadata = async ({
    metadata
  }: {
    metadata: Metadata;
  }, fee: number | StdFee | "auto" = "auto", memo?: string, funds?: Coin[]): Promise<ExecuteResult> => {
    return await this.client.execute(this.sender, this.contractAddress, {
      set_denom_metadata: {
        metadata
      }
    }, fee, memo, funds);
  };
}
