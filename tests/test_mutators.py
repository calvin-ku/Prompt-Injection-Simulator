from attack_engine.mutators import PayloadMutator


def test_random_chain_orders_encoding_last():
    mutator = PayloadMutator(seed=12345)

    chain = mutator.build_random_chain(
        allowed_mutators=["base64", "xml", "hex"],
        depth=3,
    )

    assert chain == ["xml", "base64", "hex"]