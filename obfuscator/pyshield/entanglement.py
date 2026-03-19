import random
from .utils import uid


class EntanglementSeed:
    def __init__(self):
        self._ek        = random.randint(0x100, 0xFFFF)
        self._ep        = self._next_prime(random.randint(17, 97))
        self._init_var  = uid(6)
        self._check_var = uid(6)

    @staticmethod
    def _next_prime(n: int) -> int:
        def is_prime(x):
            if x < 2: return False
            for i in range(2, int(x ** 0.5) + 1):
                if x % i == 0: return False
            return True
        while not is_prime(n):
            n += 1
        return n

    @property
    def ek(self) -> int:        return self._ek
    @property
    def ep(self) -> int:        return self._ep
    @property
    def init_var(self) -> str:  return self._init_var
    @property
    def check_var(self) -> str: return self._check_var

    def init_statements(self) -> str:
        ep, ek = self.ep, self.ek
        iv, cv = self.init_var, self.check_var
        ek_a = random.randint(1, 0x7FFF)
        ek_b = ek ^ ek_a
        ep_a = random.randint(1, ep - 1)
        ep_b = ep - ep_a
        return (
            f"{iv} = (sum(ord(__c) for __c in __name__) "
            f"* ({ep_a} + {ep_b}) + ({ek_a} ^ {ek_b})) & 0xFFFFFFFF\n"
            f"{cv} = {iv} ^ ({ek_a} ^ {ek_b})\n"
        )

    def expected_iv(self, module_name: str = "__main__") -> int:
        return (sum(ord(c) for c in module_name) * self._ep + self._ek) & 0xFFFFFFFF
