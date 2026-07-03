"""Benchmark patterns for Python reviewability (future-maintainer change risk).

Each block contains the EXACT OriginalCode from templates.go.
"""


class Config:
    pass


class Order:
    status: str
    region: str


class User:
    allowed_regions: list


def issue_refund(order: "Order") -> None:
    ...


# py-reviewability-temporal-coupling-medium - exact multi-line
class SearchClient:
    @classmethod
    def connect(cls, config: Config) -> "SearchClient":
        client = cls(config)
        client._open()
        return client

    def __init__(self, config: Config) -> None:
        self.config = config

    def _open(self) -> None:
        ...

    def index(self, document: object) -> None:
        ...

    def close(self) -> None:
        ...


# py-reviewability-divergent-policy-hard - exact multi-line
def can_refund(order: Order, user: User) -> bool:
    return order.status == "paid" and order.region in user.allowed_regions

def refund_order(order: Order, user: User) -> None:
    if not can_refund(order, user):
        raise PermissionError()
    issue_refund(order)


config = Config()
document = object()

# py-fp-reviewability-context-manager - exact multi-line
client = SearchClient.connect(config)
client.index(document)
client.close()
