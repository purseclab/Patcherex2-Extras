from patcherex2 import (
    InsertDataPatch,
    InsertFunctionPatch,
    InsertInstructionPatch,
    ModifyDataPatch,
    ModifyFunctionPatch,
    ModifyInstructionPatch,
    ModifyRawBytesPatch,
    Patcherex,
    RemoveDataPatch,
    #RemoveFunctionPatch,
    RemoveInstructionPatch,
)


def add_patch(deci):
    patch_name = ask_for_choice(deci, "What patch do you want to add?")

    binary_path = deci.binary_path
    p = Patcherex(binary_path)

    if patch_name == "ModifyRawBytesPatch":
        addr = ask_for_address(deci)
        new_bytes = ask_for_bytes(deci)
        patch = ModifyRawBytesPatch(addr, new_bytes)

    elif patch_name == "ModifyDataPatch":
        addr = ask_for_address(deci)
        new_bytes = ask_for_bytes(deci)
        patch = ModifyDataPatch(addr, new_bytes)

    elif patch_name == "InsertDataPatch":
        addr_or_name = ask_for_address_or_name(deci)
        data = ask_for_bytes(deci)
        patch = InsertDataPatch(addr_or_name, data)

    elif patch_name == "RemoveDataPatch":
        addr = ask_for_address(deci)
        size = ask_for_size(deci)
        patch = RemoveDataPatch(addr, size)

    elif patch_name == "ModifyFunctionPatch":
        addr_or_name = ask_for_address_or_name(deci)
        code = ask_for_code(deci)
        patch = ModifyFunctionPatch(addr_or_name, code)

    elif patch_name == "InsertFunctionPatch":
        addr_or_name = ask_for_address_or_name(deci)
        code = ask_for_code(deci)
        patch = InsertFunctionPatch(addr_or_name, code)

    elif patch_name == "RemoveFunctionPatch":
        display_message("Not Implemented")
        return
    
    elif patch_name == "ModifyInstructionPatch":
        addr = ask_for_address(deci)
        instr = ask_for_instructions(deci)
        patch = ModifyInstructionPatch(addr, instr)

    elif patch_name == "InsertInstructionPatch":
        addr_or_name = ask_for_address_or_name(deci)
        instr = ask_for_instructions(deci)
        patch = InsertInstructionPatch(addr_or_name, instr)

    elif patch_name == "RemoveInstructionPatch":
        addr = ask_for_address(deci)
        num_bytes = ask_for_size(deci)
        patch = RemoveInstructionPatch(addr, num_bytes)

    p.patches.append(patch)
    p.apply_patches()
    p.binfmt_tool.save_binary(binary_path + "-patched")
    display_message(deci, "Binary patched! A new file with '-patched' appended has been made. Load it to see the changes.")

def ask_for_instructions(deci, question="Instructions for the patch?", title="Patcherex2"):
    answer = deci.ghidra.bridge.remote_eval(
        "askString(title, question)", title=title, question=question, timeout_override=-1
    )
    return answer

def ask_for_code(deci, question="Code for the patch?", title="Patcherex2"):
    answer = deci.ghidra.bridge.remote_eval(
        "askString(title, question)", title=title, question=question, timeout_override=-1
    )
    return answer

def ask_for_size(deci, question="Size of the patch?", title="Patcherex2"):
    answer = deci.ghidra.bridge.remote_eval(
        "askString(title, question)", title=title, question=question, timeout_override=-1
    )
    return int(answer)

def ask_for_bytes(deci, question="Bytes to use for the patch?", title="Patcherex2"):
    answer = deci.ghidra.bridge.remote_eval(
        "askString(title, question)", title=title, question=question, timeout_override=-1
    )
    return answer.encode() if answer else b""

def ask_for_address(deci, question="Address to use for the patch? (start it with 0x)", title="Patcherex2"):
    answer = deci.ghidra.bridge.remote_eval(
        "askString(title, question)", title=title, question=question, timeout_override=-1
    )
    return int(answer, 16)

def ask_for_address_or_name(deci, question="Address or name to use for the patch? (if address, start it with 0x)", title="Patcherex2"):
    answer = deci.ghidra.bridge.remote_eval(
        "askString(title, question)", title=title, question=question, timeout_override=-1
    )

    if answer[:2] == "0x":
        return int(answer, 16)
    
    return answer

def ask_for_choice(deci, question, title="Patcherex2"):
    choices = [
        "ModifyRawBytesPatch",
        "ModifyDataPatch",
        "InsertDataPatch",
        "RemoveDataPatch",
        "ModifyFunctionPatch",
        "InsertFunctionPatch",
        "RemoveFunctionPatch",
        "ModifyInstructionPatch",
        "InsertInstructionPatch",
        "RemoveInstructionPatch",
    ]
    answer = deci.ghidra.bridge.remote_eval(
        "askChoice(title, question, choices, default)", title=title, question=question, choices=choices, default="ModifyRawBytesPatch", timeout_override=-1
    )
    return answer if answer else ""

def display_message(deci, message):
    deci.ghidra.bridge.remote_eval(
        "popup(message)", message=message, timeout_override=-1
    )