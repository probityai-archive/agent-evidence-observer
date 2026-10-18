def count_k_palindromic_numbers(n: int, k: int) -> int:
    """ Count the number of good integers containing exactly n digits.
    
    An integer x is called k-palindromic if:
    - x is a palindrome (reads the same forwards and backwards)
    - x is divisible by k
    
    An integer is called good if its digits can be rearranged to form a k-palindromic integer.
    
    Note: Integers must not have leading zeros, neither before nor after rearrangement.
    
    Args:
        n: The number of digits (1 <= n <= 10)
        k: The divisor for k-palindromic property (1 <= k <= 9)
    
    Returns:
        The count of good integers with exactly n digits
    
    >>> count_k_palindromic_numbers(3, 5)
    27
    >>> count_k_palindromic_numbers(1, 4)
    2
    >>> count_k_palindromic_numbers(5, 6)
    2468
    """
    # implementation
    import math
    from itertools import product
    # precompute factorials up to n
    fact = [1] * (n + 1)
    for i in range(2, n + 1):
        fact[i] = fact[i - 1] * i
    
    def perm_count(counts):
        total = fact[n]
        for c in counts:
            total //= fact[c]
        if counts[0] > 0:
            remain = fact[n - 1]
            # adjust for zero used as leading
            for i, c in enumerate(counts):
                if i == 0:
                    rem = c - 1
                else:
                    rem = c
                remain //= fact[rem]
            total -= remain
        return total
    
    half_len = (n + 1) // 2
    good_multisets = set()
    digits = [str(d) for d in range(10)]
    for first_half in product(digits, repeat=half_len):
        if first_half[0] == '0':
            continue
        if n % 2 == 0:
            pal = ''.join(first_half + tuple(reversed(first_half)))
        else:
            pal = ''.join(first_half + tuple(reversed(first_half[:-1])))
        if int(pal) % k != 0:
            continue
        cnt = [0] * 10
        for ch in pal:
            cnt[ord(ch) - 48] += 1
        good_multisets.add(tuple(cnt))
    total_good = 0
    for cnt in good_multisets:
        total_good += perm_count(cnt)
    return total_good