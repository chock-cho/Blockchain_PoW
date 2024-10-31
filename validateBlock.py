import json
import hashlib
import binascii
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# 키 로드 함수
def load_keys():
    # 여기에 자신의 키 파일 경로를 지정하세요
    with open("alice_key.pem", "r") as f:
        alice_key = DSA.import_key(f.read())
    return alice_key

##  Block Validation Process with Signature Verification
##  블록 검증 프로세스 -- 서명 검증
def validate_block(block_file, next_block_file, sender_key):
    with open(block_file, "r") as f:
        block = json.load(f)

    print(f"검증 중인 블록 {block['TxID']} 내용:", block)  # 검증 중인 블록 내용 출력

    # `Hash` 필드 제외 후 직렬화
    block_data = {k: v for k, v in block.items() if k != "Hash"}
    block_data_json = json.dumps(block_data, sort_keys=True, separators=(',', ':')).encode()
    computed_hash = hashlib.sha256(block_data_json).hexdigest()

    # 해시 조건 검증 및 해시 일치 여부 확인
    if int(computed_hash, 16) >= 2**248 or computed_hash != block["Hash"]:
        print(f"블록 {block['TxID']} 유효성 검증 실패: 해시 조건 불만족 또는 해시 불일치")
        return False

    # 서명 검증
    signature = binascii.unhexlify(block["Input"]["ScriptSig"])
    verifier = DSS.new(sender_key, 'fips-186-3')
    msg = block["Input"]["Previous Tx"].encode()

    try:
        verifier.verify(SHA256.new(msg), signature)
        print(f"블록 {block['TxID']} 서명 검증 성공")
    except ValueError:
        print(f"블록 {block['TxID']} 유효성 검증 실패: 서명 불일치")
        return False

    # 다음 블록 로드하여 연결 상태 확인
    with open(next_block_file, "r") as f:
        next_block = json.load(f)

    if next_block["Input"]["Previous Tx"] != block["Hash"]:
        print(f"블록 {block['TxID']} 유효성 검증 실패: 다음 블록의 Previous Tx 불일치")
        return False

    print(f"블록 {block['TxID']} 유효성 검증 성공")
    return True

# 키 로드
alice_key = load_keys()

# 모든 블록 검증
for i in range(1, 10):
    if validate_block(f"block{i}.txt", f"block{i+1}.txt", alice_key):
        print(f"Block {i} - 검증 성공")
    else:
        print(f"Block {i} - 검증 실패")
