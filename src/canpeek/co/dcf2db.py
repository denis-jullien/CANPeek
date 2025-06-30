import dcf
import cantools


def read_device_from_dcf(filename, nodeid: int):
    env = {"NODEID": nodeid}
    dev = dcf.Device.from_dcf(filename, env)
    # dev.c = CDevice(dev)
    return dev


def dcf_2_messages(filename, nodeid: int, slave_name: str):
    dev = read_device_from_dcf(filename, nodeid)

    messages = []

    for n, tpdo in dev.tpdo.items():
        # print(hex(tpdo.cob_id))

        current_len = 0
        sigs = []
        for mapn, subObject in tpdo.mapping.items():
            # print("\t", hex(subObject.index), subObject.sub_index, subObject.name)
            # debug(subObject.data_type.name(), subObject.data_type.bits())

            if "INTEGER" in subObject.data_type.name():
                is_signed = True
            else:
                is_signed = False

            sigs.append(
                cantools.db.Signal(
                    subObject.name.replace(" ", "_"),
                    current_len,
                    subObject.data_type.bits(),
                    is_signed=is_signed,
                )
            )

            current_len += subObject.data_type.bits()

        if current_len == 0:
            continue

        msg = cantools.db.Message(
            frame_id=tpdo.cob_id,
            name=f"{slave_name} TPDO {n}".replace(" ", "_"),
            length=int(current_len / 8),
            signals=sigs,
            senders=[slave_name],
        )
        messages.append(msg)

    return messages


def dcf_2_db(filename, nodeid: int, slave_name: str):
    messages = dcf_2_messages(filename, nodeid, slave_name)
    node = cantools.db.Node(slave_name)
    db = cantools.db.Database(messages, [node])
    return db
