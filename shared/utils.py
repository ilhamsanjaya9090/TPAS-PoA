import bson

def serialize_block(block):
    if isinstance(block, dict):
        return {k: serialize_block(v) for k, v in block.items()}
    elif isinstance(block, list):
        return [serialize_block(i) for i in block]
    elif isinstance(block, bson.ObjectId):
        return str(block)
    else:
        return block
