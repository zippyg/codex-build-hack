def run(input, params):
    ticket = input.partition("Ticket:")[2].lower()

    if "has a bug" in ticket:
        return "bug"
    if "arrived damaged" in ticket or "shipping question" in ticket or "where is order" in ticket:
        return "shipping"
    if "not a billing issue" not in ticket and (
        "charge" in ticket or "charged" in ticket or "billing issue" in ticket or "refund" in ticket
    ):
        return "billing"
    return "account"
