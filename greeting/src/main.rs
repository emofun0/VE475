fn quick_sort(arr: &mut [i32], partition_fn: fn(&mut [i32]) -> usize) {
    if arr.len() > 1 {
        let pivot_index = partition_fn(arr);
        quick_sort(&mut arr[..pivot_index], partition_fn);
        quick_sort(&mut arr[pivot_index + 1..], partition_fn);
    }
}

fn partition_lomuto(arr: &mut [i32]) -> usize {
    let (low, high) = (0, arr.len() as i32 - 1);
    let pivot = arr[high as usize];

    let mut swap_index = low - 1;
    for i in (low..high).map(|i| i as usize) {
        if arr[i] < pivot {
            swap_index += 1;
            arr.swap(swap_index as usize, i);
        }
    }

    arr.swap((swap_index + 1) as usize, high as usize);
    (swap_index + 1) as usize
}

fn partition_hoare(arr: &mut [i32]) -> usize {
    let pivot = arr[0];
    let mut i = 0;
    let mut j = arr.len() - 1;

    while i < j {
        while i < j && arr[i] <= pivot {
            i += 1;
        }

        while i < j && arr[j] > pivot {
            j -= 1;
        }

        if i < j {
            arr.swap(i, j);

            i += 1;
            j -= 1;
        }
    }

    if arr[i] > pivot {
        arr.swap(i - 1, 0);
        return i - 1;
    } else {
        arr.swap(i, 0);
        return i;
    }
}

fn main() {
    let mut arr = vec![30, 24, 5, 58, 18, 36, 12, 42, 39];
    quick_sort(&mut arr, partition_lomuto);
    println!("Sorted array: {:?}", arr);

    let mut arr = vec![30, 24, 5, 58, 18, 36, 12, 42, 39];
    quick_sort(&mut arr, partition_hoare);
    println!("Sorted array: {:?}", arr);
}