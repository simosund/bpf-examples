#!/bin/env python3
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os
import pathlib
import argparse
import time

import common_plotting as complot
import sar_data_loading as sdl
import sar_cpu_viz
import util

label_folder_map = {"baseline": "no_pping",
                    "PPing": "k_pping", "ePPing": "e_pping"}


def get_test_interval(sub_folder, omit=0, omit_end=1):
    start, end = None, None
    with open(os.path.join(sub_folder, "test_interval.log"), "rt") as file:
        lines = file.readlines()
    start = np.datetime64(lines[0].split("Start: ")[1][:19])
    start += np.timedelta64(omit, "s")
    end = np.datetime64(lines[1].split("End: ")[1][:19])
    end -= np.timedelta64(omit_end, "s")
    return start, end


def get_sarfile(sub_folder):
    sarfiles = list(pathlib.Path(sub_folder, "M2").glob("M2_stats.sar*"))
    if len(sarfiles) > 1:
        print("Warning: Multiple sar files in {}, returning first".format(
            os.path.join(sub_folder, "M2")))
    return sarfiles[0] if len(sarfiles) > 0 else None


def load_cpu_data(root_folder, omit=0):
    load_dict = dict()
    for label, folder in label_folder_map.items():
        subfolder = os.path.join(root_folder, folder)
        test_interval = get_test_interval(subfolder, omit)
        sarfile = get_sarfile(subfolder)
        if sarfile is None:
            continue

        j_data = sdl.load_sar_cpu_data(sarfile)
        data = sdl.to_percpu_df(j_data, filter_timerange=test_interval)

        load_dict[label] = data["all"].copy()

    return load_dict


def load_network_data(root_folder, interface="ens192", omit=0):
    net_dict = dict()
    for label, folder in label_folder_map.items():
        subfolder = os.path.join(root_folder, folder)
        test_interval = get_test_interval(subfolder, omit)
        sarfile = get_sarfile(subfolder)
        if sarfile is None:
            continue

        j_data = sdl.load_sar_network_data(get_sarfile(subfolder))
        data = sdl.to_perinterface_df(j_data, filter_timerange=test_interval)

        net_dict[label] = data[interface].copy()

    return net_dict


def parse_timestamp(date, t_str):
    """
    Returns a datetime from combining the timestring date like dateTHH:MM:SS
    """
    return np.datetime64(date + "T" + t_str, "ns")


def datetime64_truncate(dt, unit):
    return dt.astype("datetime64[{}]".format(unit)).astype(dt.dtype)


def _count_pping_messages(filename, parsing_func, keys, date=None,
                          norm_timestamps=True, filter_timerange=None,
                          **kwargs):
    """
    Count nr of rtt-events per second from some line-based output from pping.
    If passed, date should be string in YYYY-MM-DD format.
    """
    if date is None:
        date = time.strftime("%Y-%m-%d", time.gmtime())

    step_size = np.timedelta64(1, "s")
    midnight_gap_tresh = np.timedelta64(-1, "h")

    count = {"ts": list()}
    for key in keys:
        count[key] = [0]

    with util.open_compressed_file(filename, mode="rt") as file:
        for line in file:
            t, increments = parsing_func(line, date, **kwargs)
            if t is None:
                continue

            if len(count["ts"]) == 0:
                count["ts"].append(datetime64_truncate(t, "s"))

            t_diff = t - count["ts"][-1]
            if t_diff < midnight_gap_tresh:
                t += np.timedelta64(1, "D")
                t_diff = t - count["ts"][-1]

            if t_diff >= step_size:
                for missing_t in np.arange(count["ts"][-1], t+1, step_size)[1:]:
                    count["ts"].append(missing_t)
                    for key in keys:
                        count[key].append(0)

            for key in increments:
                count[key][-1] += 1

    count = pd.DataFrame(count)
    ref = None
    if filter_timerange is not None:
        count = count.loc[count["ts"].between(*filter_timerange)]
        count.reset_index(drop=True, inplace=True)
        ref = filter_timerange[0]
    if norm_timestamps:
        count["ts"] = util.normalize_timestamps(count["ts"], reference=ref)

    return count


def parse_epping_message(line, date, src_ip=None):
    words = line.split()
    if len(words) < 7:
        return None, None

    t = parse_timestamp(date, words[0])

    increments = ["all_events"]
    if words[2] == "ms":
        increments.append("rtt_events")
        if src_ip is not None and words[-1].split(":")[0] == src_ip:
            increments.append("filtered_rtt_events")

    return t, increments


def parse_kpping_message(line, date, src_ip=None):
    words = line.split()
    if len(words) != 4:
        return None, None

    t = parse_timestamp(date, words[0])

    increments = ["rtt_events"]
    if src_ip is not None and words[-1].split(":")[0] == src_ip:
        increments.append("filtered_rtt_events")

    return t, increments


def count_epping_messages(root_folder, src_ip=None, omit=0):
    """
    Count nr of rtt-events per second from the standard output of eBPF pping.
    The columns "filtered_rtt_events" is rtt-events from src_ip
    The column "all_events" includes both rtt-events and flow-events
    """

    sub_path = pathlib.Path(root_folder, "e_pping")
    test_interval = get_test_interval(sub_path, omit)
    date = str(get_test_interval(sub_path)[0])[:10]
    file = list(sub_path.glob("*M2/pping.out*"))[0]
    keys = ["all_events", "rtt_events"]
    if src_ip is not None:
        keys.append("filtered_rtt_events")

    return _count_pping_messages(file, parse_epping_message, keys, date=date,
                                 filter_timerange=test_interval, src_ip=src_ip)


def count_kpping_messages(root_folder, src_ip=None, omit=0):
    """
    Count nr of rtt-events per second from the standard output of Kathie's pping.
    The columns "filtered_rtt_events" is rtt-events from src_ip
    """

    sub_path = pathlib.Path(root_folder, "k_pping")
    test_interval = get_test_interval(sub_path, omit)
    date = str(get_test_interval(sub_path)[0])[:10]
    file = list(sub_path.glob("*M2/pping.out*"))[0]
    keys = ["rtt_events"]
    if src_ip is not None:
        keys.append("filtered_rtt_events")

    return _count_pping_messages(file, parse_kpping_message, keys, date=date,
                                 filter_timerange=test_interval, src_ip=src_ip)


def plot_network_throughput(interface_dfs, axes=None, **kwargs):
    axes = complot.plot_pergroup_timeseries(interface_dfs, "txbps", axes=axes,
                                            stat_kwargs={"fmt": "{:.3e}"},
                                            **kwargs)
    _, ymax = axes.get_ylim()
    axes.set_ylim(0, 1.05*ymax)
    axes.set_ylabel("Throughput (bps)")
    axes.set_xlabel("Time (s)")


def plot_pping_output(kpping_data, epping_data, axes=None, grid=True, legend=True):
    if axes is None:
        axes = plt.gca()

    axes.plot(kpping_data["ts"].values, kpping_data["rtt_events"].values, c="C1", ls="-", label="PPing")
    if "filtered_rtt_events" in kpping_data.columns:
        axes.plot(kpping_data["ts"].values, kpping_data["filtered_rtt_events"].values, c="C1", ls="--", label="PPing filtered")

    axes.plot(epping_data["ts"].values, epping_data["rtt_events"].values, c="C2", ls="-", label="ePPing")
    if "filtered_rtt_events" in epping_data.columns:
        axes.plot(epping_data["ts"].values, epping_data["filtered_rtt_events"].values, c="C2", ls="--", label="ePPing filtered")

    axes.set_ylim(0)
    axes.set_xlabel("Time (s)")
    axes.set_ylabel("Events per second")
    axes.grid(grid)
    if legend:
        axes.legend()

    return axes


def main():
    parser = argparse.ArgumentParser("Plot graphs comparing the performance overhead of pping versions")
    parser.add_argument("-i", "--input", type=str, help="root folder of the results from run_tests.sh", required=True)
    parser.add_argument("-o", "--output", type=str, help="image output file", required=False)
    parser.add_argument("-I", "--interface", type=str, help="interface pping is running on", default="ens192", required=False)
    parser.add_argument("-s", "--source-ip", type=str, help="src-ip used to count filtered report", required=False, default=None)
    parser.add_argument("-O", "--omit", type=int, help="nr seconds to omit from start of test", required=False, default=0)
    args = parser.parse_args()

    cpu_data = load_cpu_data(args.input, omit=args.omit)
    net_data = load_network_data(args.input, interface=args.interface,
                                 omit=args.omit)

    epping_messages = count_epping_messages(args.input, src_ip=args.source_ip,
                                            omit=args.omit)
    kpping_messages = count_kpping_messages(args.input, src_ip=args.source_ip,
                                            omit=args.omit)

    fig, axes = plt.subplots(3, 1, figsize=(8, 15), constrained_layout=True)

    sar_cpu_viz.plot_percpu_timeseries(cpu_data, axes=axes[0])
    axes[0].set_xlabel("Time (s)")
    plot_network_throughput(net_data, axes=axes[1])
    axes[1].set_xlabel("Time (s)")
    plot_pping_output(kpping_messages, epping_messages, axes=axes[2])
    fig.suptitle("Comparing performance of pping variants")

    # Hack fix for it to render correctly on older matplotlib
    # https://stackoverflow.com/a/59341086
    fig.canvas.draw()
    fig.canvas.draw()

    if args.output is not None:
        fig.savefig(args.output, bbox_inches="tight")
    else:
        plt.show()

    return


if __name__ == "__main__":
    main()
