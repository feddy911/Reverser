#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <fstream>
#include <gmp.h>

std::string mpz_to_string(mpz_t num) {
	size_t size = mpz_sizeinbase(num, 10) + 2;
	std::vector<char> buffer(size);
	mpz_get_str(buffer.data(), 10, num);
	return std::string(buffer.data());
}

class CollatzConjecture {
private:
	mpz_t number;
	unsigned long long steps;
	std::chrono::time_point<std::chrono::high_resolution_clock> startTime, endTime;
	std::vector<std::string> history;
	bool saveHistory;
	bool verbose;

public:
	mpz_t milestone;
	CollatzConjecture(bool saveHistoryEnabled = false, bool verboseEnabled = false)
		: steps(0), saveHistory(saveHistoryEnabled), verbose(verboseEnabled) {
		mpz_init(number);
	}

	~CollatzConjecture() {
		mpz_clear(number);
	}

	void setNumber(const char* numStr) {
		mpz_set_str(number, numStr, 10);
		steps = 0;
		history.clear();

		if (saveHistory) {
			saveToHistory();
		}
	}

	void setNumber(mpz_t num) {
		mpz_set(number, num);
		steps = 0;
		history.clear();

		if (saveHistory) {
			saveToHistory();
		}
	}

	void saveToHistory() {
		history.push_back(mpz_to_string(number));
	}

	bool step() {
		if (mpz_cmp_ui(number, 1) == 0) {
			return false;
		}

		if (mpz_odd_p(number)) {
			mpz_mul_ui(number, number, 3);
			mpz_add_ui(number, number, 1);
		}
		else {
			mpz_tdiv_q_2exp(number, number, 1);
		}

		steps++;

		if (saveHistory) {
			saveToHistory();
		}

		return true;
	}

	unsigned long long calculate() {
		startTime = std::chrono::high_resolution_clock::now();

		while (mpz_cmp_ui(number, 1) != 0) {
			step();

			if (steps == 10000000) {
				mpz_set(milestone, number);
			}

			if (verbose && steps % 100000 == 0) {
				std::cout << "\rSteps: " << steps << " (" << (steps / 100000) << "0%)" << std::flush;
			}
		}

		endTime = std::chrono::high_resolution_clock::now();
		return steps;
	}

	void printResults() {
		auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

		std::cout << "\n\n========================================\n";
		std::cout << "RESULTS\n";
		std::cout << "========================================\n";
		std::cout << "Number of steps: " << steps << "\n";
		std::cout << "Execution time: " << duration.count() << " ms\n";

		if (duration.count() > 0) {
			double stepsPerSecond = (steps * 1000.0) / duration.count();
			std::cout << "Speed: " << stepsPerSecond << " steps/sec\n";
		}

		size_t digitCount = mpz_sizeinbase(number, 10);
		std::cout << "Current number size: " << digitCount << " digits\n";
		std::cout << "========================================\n";
	}

	void saveHistoryToFile(const std::string& filename) {
		if (!saveHistory || history.empty()) {
			std::cerr << "Error: No history to save\n";
			return;
		}

		std::ofstream file(filename);
		if (!file.is_open()) {
			std::cerr << "Error: Cannot open file: " << filename << "\n";
			return;
		}

		int count = 0;
		for (const auto& num : history) {
			file << num << "\n";
			count++;
			if (verbose && count % 1000 == 0) {
				std::cout << "\rSaved: " << count << " records" << std::flush;
			}
		}

		file.close();
		std::cout << "\nHistory saved to file: " << filename << "\n";
		std::cout << "Total records: " << history.size() << "\n";
	}

	std::string getCurrentNumberAsString() {
		return mpz_to_string(number);
	}

	void printNumberInfo() {
		size_t digitCount = mpz_sizeinbase(number, 10);
		std::cout << "Number size: " << digitCount << " digits\n";

		if (digitCount < 50) {
			std::cout << "Number: " << mpz_to_string(number) << "\n";
		}
		else {
			std::string numStr = mpz_to_string(number);
			std::cout << "First 20 digits: " << numStr.substr(0, 20) << "...\n";
			std::cout << "Last 20 digits: ..." << numStr.substr(numStr.length() - 20) << "\n";
		}
	}

	void sumOfDigits(mpz_t result, mpz_t num) {
		char* numStr = mpz_get_str(nullptr, 10, num);

		// Инициализируем результат нулем
		mpz_set_ui(result, 0);

		// Проходим по каждому символу строки
		for (char* p = numStr; *p; p++) {
			if (*p >= '0' && *p <= '9') {
				// Добавляем цифру к результату
				unsigned long digit = *p - '0';
				mpz_add_ui(result, result, digit);
			}
		}

		// Освобождаем память, выделенную mpz_get_str
		free(numStr);
	}
};

bool find(int k, int d, unsigned __int64* oe, unsigned __int64* p2oe, int* n, int* m) { // find k1, k2: k = oe + p2oe * n (k = 2 ^ m *...)
	bool result = false;

	if (d % 2 == 1) { // odd
		for (int _n = 0; _n < 50000; _n++) {
			unsigned __int64 o = 3;
			unsigned __int64 p2o = 4;
			for (int _m = 1; _m < 256; _m += 2) {
				if (k == o + p2o * _n) {
					//if (n == 0) {
					//	printf("%05d: %llu + %llu * %d\n", k, o, p2o, n);
					//}
					//printf("%d: %llu + %llu * %d (%d) -> ", k, o, p2o, n, m);
					//int next = 3 * k + 1;
					//for (int r = 0; r < m; r++) {
					//	next /= 2;
					//}
					//printf("%d;\n", next);
					*oe = o;
					*p2oe = p2o;
					*n = _n;
					*m = _m;
					result = true;
					break;
				}
				o = 4 * o + 1;
				p2o *= 4;
			}
		}
	}
	else { // even
		for (int _n = 0; _n < 50000; _n++) {
			unsigned __int64 e = 1;
			unsigned __int64 p2e = 8;
			for (int _m = 2; _m < 256; _m += 2) {
				if (k == e + p2e * _n) {
					//if (n == 0) {
					//	printf("%05d: %llu + %llu * %d\n", k, e, p2e, n);
					//}
					//printf("%d: %llu + %llu * %d (%d) -> ", k, e, p2e, n, m);
					//int next = 3 * k + 1;
					//for (int r = 0; r < m; r++) {
					//	next /= 2;
					//}
					//printf("%d;\n", next);
					*oe = e;
					*p2oe = p2e;
					*n = _n;
					*m = _m;
					result = true;
					break;
				}
				e = 4 * e + 1;
				p2e *= 4;
			}
		}
	}
	return result;
}

int main(int argc, char* argv[]) {
	bool found = false;
	int n, m, r;
	unsigned __int64 o, e, p2o, p2e;

	for (int k = 1; k < 100000; k += 2) {
		for (int d = 1; d < 50000; d++) {
			found = find(k, d, &o, &p2o, &n, &m);
			if (found) {
				printf("%d: %llu + %llu * %d (%d) -> ", k, o, p2o, n, m);
				int next = 3 * k + 1;
				for (int r = 0; r < m; r++) {
					next /= 2;
				}
				printf("%d;\n", next);
				break;
			}
		}
		if (!found) printf("%05d: ???\n", k);
		found = false;

		//	if (d % 2 == 1) { // odd
		//		for (int n = 0; n < 8000; n++) {
		//			unsigned __int64 o = 3;
		//			unsigned __int64 p2o = 4;
		//			for (int m = 1; m < 256; m += 2) {
		//				if (k == o + p2o * n) {
		//					//if (n == 0) {
		//					//	printf("%05d: %llu + %llu * %d\n", k, o, p2o, n);
		//					//}
		//					printf("%d: %llu + %llu * %d (%d) -> ", k, o, p2o, n, m);
		//					int next = 3 * k + 1;
		//					for (int r = 0; r < m; r++) {
		//						next /= 2;
		//					}
		//					printf("%d;\n", next);
		//					found = true;
		//					break;
		//				}
		//				o = 4 * o + 1;
		//				p2o *= 4;
		//			}
		//		}
		//	}
		//	else { // even
		//		for (int n = 0; n < 8000; n++) {
		//			unsigned __int64 e = 1;
		//			unsigned __int64 p2e = 8;
		//			for (int m = 2; m < 256; m += 2) {
		//				if (k == e + p2e * n) {
		//					//if (n == 0) {
		//					//	printf("%05d: %llu + %llu * %d\n", k, e, p2e, n);
		//					//}
		//					printf("%d: %llu + %llu * %d (%d) -> ", k, e, p2e, n, m);
		//					int next = 3 * k + 1;
		//					for (int r = 0; r < m; r++) {
		//						next /= 2;
		//					}
		//					printf("%d;\n", next);
		//					found = true;
		//					break;
		//				}
		//				e = 4 * e + 1;
		//				p2e *= 4;
		//			}
		//		}
		//	}
		//	if (found) break;
		//}
		//if (!found) printf("%05d: ???\n", k);
		//found = false;
	}

	return 0;

	mpz_t power;
	mpz_init(power);
	mpz_t result;
	mpz_init(result);

	for (int n = 0; n < 1000; n++) {
		mpz_ui_pow_ui(power, 2, n);
		std::string powerStr = mpz_to_string(power);

		char* numStr = mpz_get_str(nullptr, 10, power);
		mpz_set_ui(result, 0);

		for (char* p = numStr; *p; p++) {
			if (*p >= '0' && *p <= '9') {
				// Добавляем цифру к результату
				unsigned long digit = *p - '0';
				mpz_add_ui(result, result, digit);
			}
		}

		std::string outStr = mpz_to_string(result);
		//printf("n = %d sum = %s\n", n, outStr.c_str());
		printf("n = %d power = %s;\n", n, powerStr.c_str());
	}
	return 0;

	std::cout << "========================================\n";
	std::cout << "    COLLATZ CONJECTURE TESTER\n";
	std::cout << "    (arbitrary precision integers)\n";
	std::cout << "========================================\n\n";

	if (argc < 2) {
		std::cout << "Usage: " << argv[0] << " <number> [options]\n";
		std::cout << "\nOptions:\n";
		std::cout << "  --history    save all numbers to file\n";
		std::cout << "  --info       show number information\n";
		std::cout << "  --verbose    show progress\n";
		std::cout << "\nExamples:\n";
		std::cout << "  " << argv[0] << " 27\n";
		std::cout << "  " << argv[0] << " 837799 --info\n";
		std::cout << "  " << argv[0] << " 12345678901234567890 --history\n";
		return 1;
	}

	bool saveHistory = false;
	bool showInfo = false;
	bool verbose = false;

	for (int i = 2; i < argc; i++) {
		std::string arg = argv[i];
		if (arg == "--history") saveHistory = true;
		if (arg == "--info") showInfo = true;
		if (arg == "--verbose") verbose = true;
	}

	CollatzConjecture collatz(saveHistory, verbose);

	try {
		mpz_t t;
		mpz_init(t);
		mpz_ui_pow_ui(t, 3, 2000000);
		mpz_clear(t);

		//collatz.setNumber(argv[1]);
		collatz.setNumber(t);

		std::cout << "Testing number: " << collatz.getCurrentNumberAsString() << "\n";

		if (showInfo) {
			collatz.printNumberInfo();
		}

		std::cout << "\nCalculating..." << std::endl;

		unsigned long long steps = collatz.calculate();
		collatz.printResults();

		if (saveHistory && steps > 0) {
			std::cout << "\nSaving history...\n";
			collatz.saveHistoryToFile("collatz_history.txt");
		}

		if (steps == 0) {
			std::cout << "\nNumber is already 1\n";
		}

	}
	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << "\n";
		return 1;
	}

	std::cout << "\nPress Enter to exit...";
	std::cin.get();

	return 0;
}

129: 1 + 8 * 16 (2) -> 97;  (388 * 4 ^ n - 1) / 3
517: 5 + 32 * 16 (4) -> 97;
2069: 21 + 128 * 16 (6) -> 97;
8277: 85 + 512 * 16 (8) -> 97;
33109: 341 + 2048 * 16 (10) -> 97;

67: 3 + 4 * 16 (1) -> 101;  (202 * 4 ^ n - 1) / 3
269: 13 + 16 * 16 (3) -> 101;
1077: 53 + 64 * 16 (5) -> 101;
4309: 213 + 256 * 16 (7) -> 101;
17237: 853 + 1024 * 16 (9) -> 101;
68949: 3413 + 4096 * 16 (11) -> 101;

137: 1 + 8 * 17 (2) -> 103;
549: 5 + 32 * 17 (4) -> 103;
2197: 21 + 128 * 17 (6) -> 103;
8789: 85 + 512 * 17 (8) -> 103;
35157: 341 + 2048 * 17 (10) -> 103;
