//
//  Wallet.swift
//  WalletKit
//
//  Created by yuzushioh on 2018/01/01.
//  Copyright © 2018 yuzushioh. All rights reserved.
//
import Foundation

public final class Wallet {
    
    public let privateKey: PrivateKey
    public let network: Network
    
    public init(seed: Data, network: Network) {
        self.network = network
        privateKey = PrivateKey(seed: seed, network: network)
    }
    
    //MARL: - Public
    
    public func generateAddress(at index: UInt32)  -> String {
        let derivedKey = bip44PrivateKey.derived(at: .notHardened(index))
        return derivedKey.publicKey.address
    }
    
    public func generateAccount(at index: UInt32 = 0) -> Account {
        let address = bip44PrivateKey.derived(at: .notHardened(index))
        return Account(rawPrivateKey: address.get(),
                       rawPublicKey: address.publicKey.get(),
                       address: address.publicKey.address)
    }
    
    public func generateAccounts(count: UInt32) -> [Account]  {
        var accounts:[Account] = []
        for index in 0..<count {
            accounts.append(generateAccount(at: index))
        }
        return accounts
    }
    
    //MARK: - Private
    //https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
    private var bip44PrivateKey:PrivateKey {
        let bip44Purpose:UInt32 = 44
        let purpose = privateKey.derived(at: .hardened(bip44Purpose))
        let coinType = purpose.derived(at: .hardened(network.coinType))
        let account = coinType.derived(at: .hardened(0))
        let receive = account.derived(at: .notHardened(0))
        return receive
    }
    
    private func generatePrivateKey(at nodes:[DerivationNode]) -> PrivateKey {
        return privateKey(at: nodes)
    }
    
    private func privateKey(at nodes: [DerivationNode]) -> PrivateKey {
        var key: PrivateKey = privateKey
        for node in nodes {
            key = key.derived(at:node)
        }
        return key
    }
}
