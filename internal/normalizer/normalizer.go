package normalizer

import (
	"log"
	"sync/atomic"
	"time"
	"context"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

type Config struct {
	Brokers     string
	InputTopic  string
	OutputTopic string
	GroupID     string
}

func Run(cfg Config) error {
	// Ensure topics exist
	admin, err := kafka.NewAdminClient(&kafka.ConfigMap{"bootstrap.servers": cfg.Brokers})
	if err == nil {
		topics := []kafka.TopicSpecification{
			{Topic: cfg.InputTopic, NumPartitions: 3, ReplicationFactor: 1},
			{Topic: cfg.OutputTopic, NumPartitions: 3, ReplicationFactor: 1},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err = admin.CreateTopics(ctx, topics)
		if err != nil {
			log.Printf("⚠️ Topics may already exist: %v", err)
		} else {
			log.Println("✅ Topics ensured (input/output created)")
		}
		admin.Close()
	}

	// Create consumer
	consumer, err := kafka.NewConsumer(&kafka.ConfigMap{
		"bootstrap.servers":  cfg.Brokers,
		"group.id":           cfg.GroupID,
		"auto.offset.reset":  "earliest",
		"enable.auto.commit": false, // Manual commit for reliability
	})
	if err != nil {
		return err
	}
	defer consumer.Close()

	if err := consumer.SubscribeTopics([]string{cfg.InputTopic}, nil); err != nil {
		return err
	}

	// Create producer
	producer, err := kafka.NewProducer(&kafka.ConfigMap{
		"bootstrap.servers": cfg.Brokers,
	})
	if err != nil {
		return err
	}
	defer producer.Close()

	log.Printf("🚀 Normalizer started: consuming from '%s', producing to '%s'", cfg.InputTopic, cfg.OutputTopic)

	var count uint64
	const batchSize = 100

	// Metrics goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		var last uint64
		for range ticker.C {
			current := atomic.LoadUint64(&count)
			rate := float64(current-last) / 5.0
			last = current
			log.Printf("[Metrics] %.2f msg/sec (total=%d)", rate, current)
		}
	}()

	// Consume messages
	for {
		msg, err := consumer.ReadMessage(-1)
		if err != nil {
			log.Printf("❌ Consumer error: %v", err)
			continue
		}

		normalized := ApplyStage1Rules(string(msg.Value))

		err = producer.Produce(&kafka.Message{
			TopicPartition: kafka.TopicPartition{
				Topic:     &cfg.OutputTopic,
				Partition: kafka.PartitionAny,
			},
			Value: []byte(normalized),
			Key:   msg.Key,
		}, nil)
		if err != nil {
			log.Printf("❌ Producer error: %v", err)
			continue
		}

		atomic.AddUint64(&count, 1)

		if count%batchSize == 0 {
			_, err := consumer.Commit()
			if err != nil {
				log.Printf("⚠️ Commit failed: %v", err)
			} else {
				log.Printf("✅ Committed offset after %d messages", count)
			}
		}
	}
}
