import timeit

import matplotlib.pyplot as plt

if __name__ == "__main__":
    repeats = 10
    t_range = range(1, 50)

    own_impl_compute_times = []
    own_impl_t_values = []
    for t in t_range:
        time = timeit.timeit(f"""argon2(P=b"password",
                                   S=b"salt1234",
                                   p=1,
                                   tau=8,
                                   m=8,
                                   t={t})""", setup="from argon import argon2", number=repeats)
        own_impl_compute_times.append(time / repeats)
        own_impl_t_values.append(t)

    c_impl_compute_times = []
    c_impl_t_values = []
    for t in t_range:
        time = timeit.timeit(f"""argon2.hash_password_raw(
                                    password=b"password",
                                    salt=b"salt1234",
                                    time_cost={t},
                                    memory_cost=8,
                                    parallelism=1,
                                    hash_len=8,
                                    type=argon2.low_level.Type.D)""", setup="import argon2", number=repeats)
        c_impl_compute_times.append(time / repeats)
        c_impl_t_values.append(t)

    plt.plot(own_impl_t_values, own_impl_compute_times, label="own")
    plt.plot(c_impl_t_values, c_impl_compute_times, label="OS C")
    plt.xlabel("t")
    plt.ylabel("time")
    plt.title(f"Argon2d compute times for different t value (avg over {repeats} repeats)")
    plt.legend()
    plt.show()

    # test c impl behaviour an high t values

    c_impl_compute_times = []
    c_impl_t_values = []
    for t in range(1, 5000):
        time = timeit.timeit(f"""argon2.hash_password_raw(
                                        password=b"password",
                                        salt=b"salt1234",
                                        time_cost={t},
                                        memory_cost=8,
                                        parallelism=1,
                                        hash_len=8,
                                        type=argon2.low_level.Type.D)""", setup="import argon2", number=repeats)
        c_impl_compute_times.append(time / repeats)
        c_impl_t_values.append(t)

    plt.plot(c_impl_t_values, c_impl_compute_times, label="OS C")
    plt.xlabel("t")
    plt.ylabel("time")
    plt.title(f"Argon2d compute times for different t value (avg over {repeats} repeats)")
    plt.legend()
    plt.show()
