package normalizer

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

type Config struct {
	Brokers     string
	InputTopic  string
	OutputTopic string
	GroupID     string
}

func Run(cfg Config) error {
	admin, err := kafka.NewAdminClient(&kafka.ConfigMap{"bootstrap.servers": cfg.Brokers})
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		topics := []kafka.TopicSpecification{
			{Topic: cfg.InputTopic, NumPartitions: 1, ReplicationFactor: 1},
			{Topic: cfg.OutputTopic, NumPartitions: 1, ReplicationFactor: 1},
		}

		if _, err := admin.CreateTopics(ctx, topics); err != nil {
			log.Printf("Warning: Could not create topics: %v", err)
		} else {
			log.Printf("Topics Created: %s, %s", cfg.InputTopic, cfg.OutputTopic)
		}
		admin.Close()
	} else {
		log.Printf("Client Unavailable for checking : %v", err)
	}

	consumer, err := kafka.NewConsumer(&kafka.ConfigMap{
		"bootstrap.servers":  cfg.Brokers,
		"group.id":           cfg.GroupID,
		"auto.offset.reset":  "earliest",
		"enable.auto.commit": false,
	})
	if err != nil {
		return err
	}
	defer consumer.Close()

	if err := consumer.SubscribeTopics([]string{cfg.InputTopic}, nil); err != nil {
		return fmt.Errorf("failed to subscribe: %w", err)
	}

	producer, err := kafka.NewProducer(&kafka.ConfigMap{
		"bootstrap.servers":  cfg.Brokers,
		"enable.idempotence": true,
		"compression.type":   "lz4",
		"linger.ms":          10,
		"batch.num.messages": 5000,
	})

	if err != nil {
		return fmt.Errorf("failed to create producer: %w", err)
	}
	defer producer.Close()

	log.Printf("Normalizer starting...")

	// Metrics
	var msgCount uint64
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		var last uint64
		for range ticker.C {
			cur := atomic.LoadUint64(&msgCount)
			rate := float64(cur-last) / 5.0
			last = cur
			log.Printf("[Metrics] %.2f msg/sec (total=%d)", rate, cur)
		}
	}()

	// --- Delivery report handler (async errors)
	go func() {
		for e := range producer.Events() {
			switch ev := e.(type) {
			case *kafka.Message:
				if ev.TopicPartition.Error != nil {
					log.Printf("❌ Delivery failed: %v", ev.TopicPartition.Error)
				}
			}
		}
	}()

	const commitBatch = 500
	for {
		msg, err := consumer.ReadMessage(-1)
		if err != nil {
			log.Printf("Consumer Error: %v", err)
			continue
		}

		normalized := ApplyRules(string(msg.Value))

		err = producer.Produce(&kafka.Message{
			TopicPartition: kafka.TopicPartition{
				Topic:     &cfg.OutputTopic,
				Partition: kafka.PartitionAny,
			},
			Value: []byte(normalized),
			Key:   msg.Key,
		}, nil)

		if err != nil {
			log.Printf("Message Produce Error: %v", err)
			continue
		}

		atomic.AddUint64(&msgCount, 1)

		if msgCount%commitBatch == 0 {
			if _, err := consumer.Commit(); err != nil {
				log.Printf("⚠️ Commit failed: %v", err)
			} else {
				log.Printf("✅ Committed offsets after %d messages", msgCount)
			}
		}
	}
}
