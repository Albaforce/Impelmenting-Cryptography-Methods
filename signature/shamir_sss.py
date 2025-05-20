    try:
        # Parameters
        secret_message = "MyTopSecretPassword123!"
        # Convert secret string to integer. Ensure prime is large enough.        secret_int = int.from_bytes(secret_message.encode(\'utf-8\'), \'big\')        k = 3  # Threshold: 3 shares needed
        n = 5  # Total shares: 5 generated
        prime = get_sss_prime()

        print(f"Secret Message: {secret_message}")
        print(f"Secret as Integer: {secret_int}")
        print(f"Threshold (K): {k}")