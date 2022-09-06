package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

type req_time struct {
	reqlh_start        float64
	reqlh_start_grpc   float64
	reqlh_end_grpc     float64
	reqlh_end          float64
	reqb_start         float64
	reqb_start_grpc    float64
	reqb_end_grpc      float64
	reqb_end           float64
	request_start      float64
	request_start_grpc float64
	request_end_grpc   float64
	request_end        float64
	check_start        float64
	check_start_grpc   float64
	check_end_grpc     float64
	check_end          float64
	start_modsec       float64
}

func main() {
	file, err := os.Open("httpd_log")
	results := make(map[string]*req_time)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	scanner := bufio.NewScanner(file)

	scanner.Split(bufio.ScanLines)
	var line string
	for scanner.Scan() {
		line = scanner.Text()
		line_s := strings.Split(line, "[")
		//fmt.Println(len(line_s))
		if len(line_s) > 5 {
			if strings.Split(line_s[4], " ")[2] == "mod_wace_time" { //it is a mod_wace_time log line,
				fmt.Println(strings.Split(line_s[5], ":")[1])
				time_data := strings.Split(strings.Split(line_s[5], ":")[1], ",")
				fmt.Println(time_data)
				transact_id := strings.Split(line_s[5], "]")[0]
				if _, hasValue := results[transact_id]; !hasValue {
					results[transact_id] = new(req_time)
					results[transact_id].check_end = 0
					results[transact_id].check_end_grpc = 0
					results[transact_id].check_start = 0
					results[transact_id].check_start_grpc = 0
					results[transact_id].reqb_end = 0
					results[transact_id].reqb_end_grpc = 0
					results[transact_id].reqb_start = 0
					results[transact_id].reqb_start_grpc = 0
					results[transact_id].reqlh_end = 0
					results[transact_id].reqlh_end_grpc = 0
					results[transact_id].reqlh_start = 0
					results[transact_id].reqlh_start_grpc = 0
					results[transact_id].request_start = 0
				}
				switch time_data[0] {
				case "start":
					switch time_data[1] {
					case "reqlineheaders":
						switch time_data[2] {
						case "grpc":
							r, _ := strconv.ParseFloat(time_data[3], 64)
							results[transact_id].reqlh_start_grpc = r
						default:
							r, _ := strconv.ParseFloat(time_data[2], 64)
							results[transact_id].reqlh_start = r
						}
					case "reqbody":
						switch time_data[2] {
						case "grpc":
							r, _ := strconv.ParseFloat(time_data[3], 64)
							results[transact_id].reqb_start_grpc = r
						default:
							r, _ := strconv.ParseFloat(time_data[2], 64)
							results[transact_id].reqb_start = r
						}
					case "request":
						switch time_data[2] {
						case "grpc":
							r, _ := strconv.ParseFloat(time_data[3], 64)
							results[transact_id].request_start_grpc = r
						default:
							r, _ := strconv.ParseFloat(time_data[2], 64)
							results[transact_id].request_start = r
						}
					case "check":
						switch time_data[2] {
						case "grpc":
							r, _ := strconv.ParseFloat(time_data[3], 64)
							results[transact_id].check_start_grpc = r
						default:
							r, _ := strconv.ParseFloat(time_data[2], 64)
							results[transact_id].check_start = r
						}
					}

				case "end":
					switch time_data[1] {
					case "reqlineheaders":
						switch time_data[2] {
						case "grpc":
							r, _ := strconv.ParseFloat(time_data[3], 64)
							results[transact_id].reqlh_end_grpc = r
						default:
							r, _ := strconv.ParseFloat(time_data[2], 64)
							results[transact_id].reqlh_end = r
						}
					case "reqbody":
						switch time_data[2] {
						case "grpc":
							r, _ := strconv.ParseFloat(time_data[3], 64)
							results[transact_id].reqb_end_grpc = r
						default:
							r, _ := strconv.ParseFloat(time_data[2], 64)
							results[transact_id].reqb_end = r
						}
					case "request":
						switch time_data[2] {
						case "grpc":
							r, _ := strconv.ParseFloat(time_data[3], 64)
							results[transact_id].request_end_grpc = r
						default:
							r, _ := strconv.ParseFloat(time_data[2], 64)
							results[transact_id].request_end = r
						}
					case "check":
						switch time_data[2] {
						case "grpc":
							r, _ := strconv.ParseFloat(time_data[3], 64)
							results[transact_id].check_end_grpc = r
						default:
							r, _ := strconv.ParseFloat(time_data[2], 64)
							results[transact_id].check_end = r
							r, _ = strconv.ParseFloat(time_data[3], 64)
							results[transact_id].start_modsec = r
						}
					}
				}

				/*
					transact_id = strings.Split(line_s[5], "]")[0]
					time_data = strings.Split(line_s[5], ":")[1]
					results
					results[]*/
			}
		}
		//fmt.Println(scanner.Text())
	}
	fmt.Println("transact_id,total_time,mod_wace,modsecurity,wacecore_models_grpc")
	for k, value := range results {

		//fmt.Println(k)
		if value.check_end != 0 { //the request finished
			total_time := (value.check_end - value.start_modsec) * 0.000001
			//fmt.Print("//Total Time")
			//fmt.Printf("%8f\n", total_time)
			mod_wace := ((value.reqlh_start_grpc - value.reqlh_start) + (value.reqlh_end - value.reqlh_end_grpc) +
				(value.reqb_start_grpc - value.reqb_start) + (value.reqb_end - value.reqb_end_grpc) +
				(value.check_start_grpc - value.check_start) + (value.check_end - value.check_end_grpc) +
				(value.reqb_start_grpc - value.reqb_start) + (value.reqb_end - value.reqb_end_grpc) +
				(value.request_start_grpc - value.request_start) + (value.request_end - value.request_end_grpc)) * 0.000001
			//fmt.Print("//Mod Wace")
			//fmt.Printf("%8f\n", mod_wace)
			core := ((value.reqlh_end_grpc - value.reqlh_start_grpc) +
				(value.reqb_end_grpc - value.reqb_start_grpc) +
				(value.check_end_grpc - value.check_start_grpc) +
				(value.request_end_grpc - value.request_start_grpc)) * 0.000001
			//fmt.Print("//Core")
			//fmt.Printf("%8f\n", core)
			modsec := total_time - core - mod_wace
			//fmt.Print("//ModSec")
			//fmt.Printf("%8f\n", modsec)
			fmt.Printf("%v,%.10f,%.10f,%.10f,%.10f\n", k, total_time, mod_wace, modsec, core)
		} else {

			//no data
		}
		//fmt.Print(k)
		//fmt.Println(value)
	}
	file.Close()
}
