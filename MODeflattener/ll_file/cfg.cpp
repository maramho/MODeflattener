#include <stdio.h>
#include <klee/klee.h>

int main() {
    int input;

    // 심볼릭 변수로 설정
    klee_make_symbolic(&input, sizeof(input), "input");

    // input 값은 0 이상 100 이하로 제한
    klee_assume(input >= 0);
    klee_assume(input <= 100);

    int state = 0;
    int result = 0;

    while (state != -1) {
        switch (state) {
            case 0:
                if (input > 0 && input <= 10) {
                    state = 1;
                } else if (input > 10) {
                    state = 2;
                } else {
                    state = -1;
                }
                break;

            case 1:
                for (int i = 0; i < input; i++) {
                    result += i;
                }
                state = -1;
                break;

            case 2:
                while (input > 10) {
                    result += input;
                    input--;
                }
                state = -1;
                break;

            default:
                state = -1;
                break;
        }
    }

    printf("Result: %d\n", result);
    return 0;
}