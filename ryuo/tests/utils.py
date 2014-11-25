import re


def name_to_dpid(name):
    nums = re.findall(r'\d+', name)
    if nums:
        return int(nums[0])