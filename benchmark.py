import timeit
import time

import matplotlib.pyplot as plt


def bench(kwargs, code_str, setup_str, repeats=100):
    compute_times = []
    avg = None

    for name, value in kwargs.items():
        if name[-6:] == "_range":
            args = dict(kwargs)
            del args[name]
            val_name = name[:-6]
            for i, v in enumerate(value):
                if i > 0:
                    avg = sum(compute_times) / i

                print(f"\r{val_name}: {v} [{i}/{len(value)}] avg. {avg}", sep=" ", end="", flush=True)

                args[val_name] = v
                time = timeit.timeit(code_str.format(**args), setup=setup_str, number=repeats)
                compute_times.append(time / repeats)
            print()

    return compute_times


def bench_own_impl(repeats=100, **kwargs):
    print("own impl")

    defaults = {
        "force_single_process": False
    }

    code_str = """argon2(P=b"password",
                          S=b"salt1234",
                          p={p},
                          tau={tau},
                          m={m},
                          t={t},
                          force_single_process={force_single_process})"""

    setup_str = "from argon import argon2"

    for key, val in defaults.items():
        if key not in kwargs:
            kwargs[key] = val

    return bench(kwargs, code_str, setup_str, repeats=repeats)


def bench_c_impl(repeats=100, **kwargs):
    print("c lib bench")

    defaults = {
    }

    code_str = """argon2.hash_password_raw(
                                        password=b"password",
                                        salt=b"salt1234",
                                        time_cost={t},
                                        memory_cost={m},
                                        parallelism={p},
                                        hash_len={tau},
                                        type=argon2.low_level.Type.D)"""

    setup_str = "import argon2"

    for key, val in defaults.items():
        if key not in kwargs:
            kwargs[key] = val

    return bench(kwargs, code_str, setup_str, repeats=repeats)


def plot_time_results(values, timings, labels, value_label, title):
    for v, t, l in zip(values, timings, labels):
        plt.plot(v, t, label=l)
    plt.xlabel(value_label)
    plt.xticks(values[0])
    plt.ylabel("time")
    plt.title(title)
    plt.legend()
    plt.show()
    plt.savefig(f"plots/{time.strftime('%Y%m%d-%H%M%S')}.png")
    plt.clf()


def hash_length_bench():
    res = bench_own_impl(repeats=100,
                         p=1,
                         tau_range=[2 ** i for i in range(2, 10)],
                         m=8,
                         t=1)

    plot_time_results(
        [list([2 ** i for i in range(2, 10)])],
        [res],
        ["single process"],
        "tau",
        f"Argon2d compute times for different small hash length (avg over {100} repeats)"
    )

    res = bench_own_impl(repeats=10,
                         p=1,
                         tau_range=[2 ** i for i in range(2, 16)],
                         m=8,
                         t=1)

    plot_time_results(
        [list([2 ** i for i in range(2, 16)])],
        [res],
        ["single process"],
        "tau",
        f"Argon2d compute times for different hash length (avg over {10} repeats)"
    )


def c_lib_bench():
    res_c = bench_c_impl(repeats=10,
                         p=1,
                         tau=64,
                         m=32,
                         t_range=range(1, 50))

    res_parallel = bench_own_impl(repeats=10,
                                  p=1,
                                  tau=64,
                                  m=32,
                                  t_range=range(1, 50))

    plot_time_results(
        [list(range(1, 50)), list(range(1, 50))],
        [res_c, res_parallel],
        ["c lib 1 processes", "1 processes"],
        "t",
        f"Argon2d compute times for different t (avg over {10} repeats)"
    )

    res_c = bench_c_impl(repeats=10,
                         p=2,
                         tau=64,
                         m=32,
                         t_range=range(1, 50))

    res_parallel = bench_own_impl(repeats=10,
                                  p=2,
                                  tau=64,
                                  m=32,
                                  t_range=range(1, 50))

    plot_time_results(
        [list(range(1, 50)), list(range(1, 50))],
        [res_c, res_parallel],
        ["c lib 2 processes", "2 processes"],
        "t",
        f"Argon2d compute times for different t (avg over {10} repeats)"
    )

    res_c = bench_c_impl(repeats=10,
                         p=4,
                         tau=64,
                         m=32,
                         t_range=range(1, 50))

    res_parallel = bench_own_impl(repeats=10,
                                  p=4,
                                  tau=64,
                                  m=32,
                                  t_range=range(1, 50))

    plot_time_results(
        [list(range(1, 50)), list(range(1, 50))],
        [res_c, res_parallel],
        ["c lib 4 processes", "4 processes"],
        "t",
        f"Argon2d compute times for different t (avg over {10} repeats)"
    )

    res_c = bench_c_impl(repeats=10,
                         p=1,
                         tau=64,
                         m=32,
                         t_range=range(1, 500))

    plot_time_results(
        [list(range(1, 500))],
        [res_c],
        ["c lib 1 processes"],
        "t",
        f"Argon2d compute times for different t (avg over {10} repeats)"
    )


def parallelism_bench():
    res_single_2 = bench_own_impl(repeats=10,
                         p=2,
                         tau=64,
                         m=16,
                         t_range=range(1, 50),
                         force_single_process=True)

    res_parallel_2 = bench_own_impl(repeats=10,
                                  p=2,
                                  tau=64,
                                  m=16,
                                  t_range=range(1, 50))

    res_single_4 = bench_own_impl(repeats=10,
                         p=4,
                         tau=64,
                         m=32,
                         t_range=range(1, 50),
                         force_single_process=True)

    res_parallel_4 = bench_own_impl(repeats=10,
                                  p=4,
                                  tau=64,
                                  m=32,
                                  t_range=range(1, 50))
                                  
    res_single_8 = bench_own_impl(repeats=10,
                         p=8,
                         tau=64,
                         m=64,
                         t_range=range(1, 50),
                         force_single_process=True)

    res_parallel_8 = bench_own_impl(repeats=10,
                                  p=8,
                                  tau=64,
                                  m=64,
                                  t_range=range(1, 50))

    plot_time_results(
        [list(range(1, 50)), list(range(1, 50)), list(range(1, 50)), list(range(1, 50)), list(range(1, 50)), list(range(1, 50))],
        [res_single_2, res_parallel_2, res_single_4, res_parallel_4, res_single_8, res_parallel_8],
        ["single process p=2", "multiprocess p=2", "single process p=4", "multiprocess p=4", "single process p=8", "multiprocess p=8"],
        "t",
        f"Argon2d compute times for different t (avg over {10} repeats)"
    )


if __name__ == "__main__":
    hash_length_bench()
    c_lib_bench()
    parallelism_bench()
