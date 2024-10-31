import json
import hashlib
import binascii
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

## Genesis Block Generation Process
## 최초 블록 생성 프로세스 함수
def create_genesis_block(alice_key):
    genesis_block = {
        "TxID": 0,
        "Nonce": 0,
        "Output": {
            "Value": 10,
            "ScriptPubKey": f"{alice_key.y} OP_CHECKSIG"
        }
    }

    # Nonce 찾기 루프
    while True:
        block_data = json.dumps(genesis_block, sort_keys=True, separators=(',', ':')).encode()
        hash_result = hashlib.sha256(block_data).hexdigest()
        if int(hash_result, 16) < 2**248:
            genesis_block["Hash"] = hash_result
            break
        genesis_block["Nonce"] += 1

    with open("block0.txt", "w") as f:
        json.dump(genesis_block, f, sort_keys=True, separators=(',', ':'))

    return genesis_block["Hash"]

## Block Generation Process
## 블록 생성 함수
def create_block(tx_id, prev_hash, sender_key, recipient_pub_key, val, remained_val):
    block = {
        "TxID": tx_id,
        "Nonce": 0,
        "Input": {
            "Previous Tx": prev_hash,
            "Index": 0,
            "ScriptSig": ""
        },
        "Output": [
            {
                "Value": val,
                "ScriptPubKey": f"{recipient_pub_key} OP_CHECKSIG"
            },
            {
                "Value": remained_val,
                "ScriptPubKey": f"{sender_key.y} OP_CHECKSIG"
            }
        ]
    }

    # 서명 생성 및 ScriptSig에 저장
    msg = prev_hash.encode()
    signer = DSS.new(sender_key, 'fips-186-3')
    signature = signer.sign(SHA256.new(msg))
    block["Input"]["ScriptSig"] = binascii.hexlify(signature).decode()

    # Nonce 찾기 루프
    while True:
        block_data = json.dumps(block, sort_keys=True, separators=(',', ':')).encode()
        hash_result = hashlib.sha256(block_data).hexdigest()
        if int(hash_result, 16) < 2**248:
            block["Hash"] = hash_result
            break
        block["Nonce"] += 1

    with open(f"block{tx_id}.txt", "w") as f:
        json.dump(block, f, sort_keys=True, separators=(',', ':'))

    return block["Hash"]

# Alice와 Bob의 키 생성 - PEM 파일로 저장
alice_key = DSA.generate(1024)
bob_key = DSA.generate(1024)
with open("alice_key.pem", "w") as f:
    f.write(alice_key.export_key(format='PEM').decode())

with open("bob_key.pem", "w") as f:
    f.write(bob_key.export_key(format='PEM').decode())

prev_hash = create_genesis_block(alice_key)
remained_val = 10  # 초기 코인 수

# 블록 생성
for i in range(1, 11):
    prev_hash = create_block(i, prev_hash, alice_key, bob_key.y, 1, remained_val - 1)
    remained_val -= 1